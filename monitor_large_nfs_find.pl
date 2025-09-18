#!/usr/bin/env perl
# monitor_large_nfs_find.pl
# NFS-friendly: без du; поиск ТОЛЬКО больших файлов + кэш известных (NEW/GROWTH)
# Плюс TOP "жирных" папок (по сумме файлов) — с ограничениями (depth/limit).
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Корни для поиска
my @ROOT_DIRS = (
    '/data',      # ← замените под себя (можно несколько)
);

# Порог "большого файла"
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;  # 2 GiB

# Повторно уведомлять, если рост ≥ столько (1 = любое увеличение)
my $MIN_FILE_GROWTH_BYTES = 1;

# Ограничение области поиска (важно для NFS)
my $MAX_DEPTH         = 6;     # глубина обхода (0=только корень, 1=дети, …)
my $FOLLOW_SYMLINKS   = 0;     # 0 — не следовать симлинкам (безопаснее на NFS)
my $XDEV              = 0;     # 1 — не пересекать другие FS

# Исключения (регэкспы Perl, применяются к абсолютному пути)
my @EXCLUDE_DIR_PATTERNS = (
    qr{/\.(git|svn|hg)(/|$)},
    qr{/tmp(/|$)},
    # qr{/data/old_backups(/|$)},
);

# ===== TOP "жирных" папок =====
my $DIR_TALLY_ENABLE      = 1;                      # 1 = включить сбор топ папок
my $DIR_TALLY_MAX_DEPTH   = 6;                      # глубина для подсчёта папок (обычно = $MAX_DEPTH)
my $DIR_TALLY_FILE_LIMIT  = 200000;                 # защитный лимит файлов (на запуск)
my $DIR_TALLY_TOP_N       = 20;                     # показать ТОП N папок
my $DIR_TALLY_MIN_BYTES   = $THRESHOLD_BYTES;       # минимальный размер папки для отчёта (важно!)
# Группировка по уровню относительно корня (0=сам корень, 1=/data/<proj>, 2=/data/<proj>/<svc> …)
# Для структуры /data/project/log/... поставьте 2, чтобы видеть аккуратно "/data/p/log"
my $DIR_GROUP_DEPTH_FROM_ROOT = 2;

# Email
my $RECIPIENTS     = 'ops@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files on NFS';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# Состояние (кэш известных крупных файлов)
my $STATE_DIR        = '/var/lib/monitor_large';
my $STATE_FILE_INDEX = "$STATE_DIR/file_index.db";  # строки: dev:ino|size|mtime|path

# Debug / Preview
my $DEBUG_PREVIEW     = 1;   # 1 — показать письмо (всегда удобно при настройке)
my $DRY_RUN           = 0;   # 1 — не отправлять
my $PREVIEW_TO_STDERR = 1;
my $DEBUG_FIND_TRACE  = 1;   # 1 — показать «какой find я запускаю» и сколько нашлось
# =================== END CONFIG =====================

# ---------------------- Утилиты ----------------------
sub ensure_state_dir { my ($d)=@_; return if -d $d; make_path($d) or die "create $d: $!" }

sub human_size {
    my ($b)=@_;
    my @u=qw(B K M G T P); my($v,$i)=($b+0,0);
    while($v>=1024 && $i<$#u){ $v/=1024; $i++ }
    return $i? sprintf("%.2f %s",$v,$u[$i]) : sprintf("%d %s",$b,$u[$i]);
}
sub format_time { my($e)=@_; defined $e ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($e)) : 'unknown' }

# Индекс крупных файлов: dev:ino -> {size,mtime,path}
sub load_file_index {
    my ($path)=@_;
    my %idx;
    if (-f $path) {
        open my $fh,'<',$path or die "open $path: $!";
        while (my $l=<$fh>) {
            chomp $l; next unless $l;
            my ($k,$s,$m,$p) = split(/\|/,$l,4);
            $idx{$k} = { size=>($s||0)+0, mtime=>($m||0)+0, path=>$p };
        }
        close $fh;
    }
    return \%idx;
}
sub save_file_index {
    my ($path,$h)=@_;
    open my $fh,'>',$path or die "write $path: $!";
    flock($fh,LOCK_EX) or die "lock $path: $!";
    for my $k (sort keys %$h) {
        my $r = $h->{$k};
        printf {$fh} "%s|%d|%d|%s\n", $k, $r->{size}+0, $r->{mtime}+0, ($r->{path}//'');
    }
    close $fh;
}
sub file_key { my($dev,$ino)=@_; return "$dev:$ino" }

sub path_is_excluded {
    my ($path)=@_;
    for my $re (@EXCLUDE_DIR_PATTERNS) {
        return 1 if $path =~ $re;
    }
    return 0;
}

# Найти общий корень для пути (самый длинный, из @ROOT_DIRS)
sub match_root_prefix {
    my ($path)=@_;
    my $best;
    for my $r (@ROOT_DIRS) {
        next unless index($path, $r) == 0;
        $best = $r if !defined($best) || length($r) > length($best);
    }
    return $best;
}

# Сгруппировать путь файла в "узел" глубины N относительно корня
sub group_dir_by_depth {
    my ($file_dir)=@_;
    my $root = match_root_prefix($file_dir) // return $file_dir;
    my $rel  = substr($file_dir, length($root));
    $rel =~ s{^/}{};
    my @parts = grep { length($_) } split m{/+}, $rel;
    if (@parts <= $DIR_GROUP_DEPTH_FROM_ROOT) {
        return ($root =~ m{/$}) ? "$root$rel" : ($rel ? "$root/$rel" : $root);
    }
    my @take = @parts[0 .. $DIR_GROUP_DEPTH_FROM_ROOT-1];
    my $grel = join('/', @take);
    return ($root =~ m{/$}) ? "$root$grel" : "$root/$grel";
}

# ---------- Поиск больших файлов (GNU find) ----------
# Возвращает [{ path, size, mtime, ctime, dev, ino }, ...]
sub find_large_files {
    my ($roots_ref, $threshold, $maxdepth)=@_;
    my @roots = @$roots_ref;
    my @found;

    my @common;
    push @common, ('-xdev') if $XDEV;
    push @common, ('-maxdepth', $maxdepth) if defined $maxdepth;
    push @common, ('-ignore_readdir_race');

    for my $root (@roots) {
        next unless -d $root;

        my @cmd = ('find');
        push @cmd, $FOLLOW_SYMLINKS ? ('-L') : ();  # симлинки не трогаем по умолчанию
        push @cmd, ($root, @common, '-type', 'f', '-size', '+'.($threshold.'c'),
                    # NB: берём только путь, всё остальное из lstat (надёжнее на разных find)
                    '-printf', '%p\0');

        if ($DEBUG_FIND_TRACE) {
            my $cmds = join(' ', map { /\s/ ? "'$_'" : $_ } @cmd);
            warn "[TRACE] find cmd: $cmds\n";
        }

        my $pid = open(my $fh, "-|", @cmd);
        if (!$pid) { warn "Cannot run find @cmd: $!"; next; }

        local $/ = "\0";
        my $local_cnt = 0;
        while (defined(my $path = <$fh>)) {
            chomp $path;
            next if path_is_excluded($path);
            my @st = lstat($path);  # для размера/времён/dev/ino
            next unless @st;
            my ($dev,$ino,$sz,$mt,$ct) = @st[0,1,7,9,10];
            next unless defined $sz && $sz >= $threshold;
            push @found, {
                path  => $path,
                size  => $sz,
                mtime => $mt,
                ctime => $ct,
                dev   => $dev,
                ino   => $ino,
            };
            $local_cnt++;
        }
        close $fh;
        warn "[TRACE] found $local_cnt files >= ".human_size($threshold)." in $root\n" if $DEBUG_FIND_TRACE;
    }
    return \@found;
}

# ---------- Подсчёт "жирных" директорий (сумма файлов) ----------
# Возвращает массив пар [dir_path, total_bytes], отсортированный по убыванию.
# Группируем по каталогу-«узлу» на глубине $DIR_GROUP_DEPTH_FROM_ROOT.
sub tally_large_dirs {
    my ($roots_ref, $maxdepth, $file_limit)=@_;
    my @roots = @$roots_ref;
    my %sum;
    my $count = 0;

    my @common;
    push @common, ('-xdev') if $XDEV;
    push @common, ('-maxdepth', $maxdepth) if defined $maxdepth;
    push @common, ('-ignore_readdir_race');

    ROOT: for my $root (@roots) {
        next unless -d $root;
        my @cmd = ('find');
        push @cmd, $FOLLOW_SYMLINKS ? ('-L') : ();
        push @cmd, ($root, @common, '-type', 'f', '-printf', '%h\0'); # только директория файла

        if ($DEBUG_FIND_TRACE) {
            my $cmds = join(' ', map { /\s/ ? "'$_'" : $_ } @cmd);
            warn "[TRACE] tally cmd: $cmds\n";
        }

        my $pid = open(my $fh, "-|", @cmd);
        if (!$pid) { warn "Cannot run find @cmd: $!"; next; }

        local $/ = "\0";
        while (defined(my $dir = <$fh>)) {
            chomp $dir;
            next if path_is_excluded($dir);
            # lstat ещё раз — получить размер файла родителя нельзя,
            # поэтому берём размер файла через stat самого файла — но у нас тут только %h.
            # Решение: пройдём тем же find, но мы выбрали «дёшевый» путь.
            # => Поднимем второй проход, который уже отдаёт %s и %h вместе.
            # Чтобы не удваивать обход, ниже делаем второй (суммарный) find сразу.

            # Остановимся — мы здесь только собираем список директорий,
            # а суммировать будем во втором вызове (ниже). Выходим из этого цикла, чтобы не плодить лишних операций.
            # Но чтобы остаться NFS-дружелюбными — см. реализацию ниже.
        }
        close $fh;

        # Реальный подсчёт: одним проходом по файлам с размерами
        @cmd = ('find');
        push @cmd, $FOLLOW_SYMLINKS ? ('-L') : ();
        push @cmd, ($root, @common, '-type', 'f', '-printf', '%s\t%h\0'); # размер и его директория

        if ($DEBUG_FIND_TRACE) {
            my $cmds = join(' ', map { /\s/ ? "'$_'" : $_ } @cmd);
            warn "[TRACE] tally cmd (sizes): $cmds\n";
        }

        $pid = open($fh, "-|", @cmd);
        if (!$pid) { warn "Cannot run find @cmd: $!"; next; }

        while (defined(my $rec = <$fh>)) {
            chomp $rec;
            my ($sz, $fdir) = split(/\t/, $rec, 2);
            next unless defined $fdir && defined $sz;
            next if path_is_excluded($fdir);

            my $group = group_dir_by_depth($fdir);
            $sum{$group} += int($sz);

            $count++;
            if ($file_limit && $count >= $file_limit) {
                close $fh;
                last ROOT;
            }
        }
        close $fh;
    }

    my @pairs = map { [$_, $sum{$_}] } keys %sum;
    @pairs = sort { $b->[1] <=> $a->[1] } @pairs;
    return \@pairs;
}

# ---------- Письмо ----------
sub build_email_message {
    my (%a)=@_;
    my ($from,$to,$subj,$body,$date)=@a{qw/from to_csv subject body_text date_header/};
    $to//= ''; $to=~s/\s+//g; $to=~s/,/, /g;
    return "From: $from\nTo: $to\nSubject: $subj\nDate: $date\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\n$body";
}
sub preview_print { my($t,$err)=@_; my $io=$err?*STDERR:*STDOUT; print $io "================= EMAIL PREVIEW BEGIN =================\n$t\n================= EMAIL PREVIEW  END  =================\n" }

# ===================== MAIN =====================
ensure_state_dir($STATE_DIR);
my $hostname = do{ my $h=`hostname`; chomp $h; $h; };
my $utc_now  = strftime("%Y-%m-%d %H:%M:%S %Z", localtime(time));

# 1) Кэш известных крупных файлов
my $idx_ref = load_file_index($STATE_FILE_INDEX); my %idx=%$idx_ref;

# 2) Проверка известных (дёшево на NFS)
my @events;   # {path,size,mtime,ctime,prev_size?,delta?,kind,dev,ino}
my %seen_keys;
for my $k (keys %idx) {
    my $info = $idx{$k};
    my $p = $info->{path} // next;
    next unless -f $p;
    my @st = lstat($p) or next;
    my ($dev,$ino,$sz,$mt,$ct) = @st[0,1,7,9,10];
    my $curr_k = file_key($dev,$ino);
    $seen_keys{$curr_k} = 1;
    my $delta = $sz - ($info->{size}//0);
    if ($delta >= $MIN_FILE_GROWTH_BYTES) {
        push @events, { path=>$p, size=>$sz, mtime=>$mt, ctime=>$ct, dev=>$dev, ino=>$ino,
                        prev_size=>$info->{size}, delta=>$delta, kind=>'GROWTH' };
    }
}

# 3) Поиск новых больших файлов (ограниченной глубиной)
my $found = find_large_files(\@ROOT_DIRS, $THRESHOLD_BYTES, $MAX_DEPTH);

# 4) NEW / GROWTH для найденных
for my $h (@$found) {
    my $k = file_key($h->{dev}, $h->{ino});
    next if $seen_keys{$k};          # уже проверили как известный
    my $prev = $idx{$k};
    if (!$prev) {
        push @events, { %$h, prev_size=>undef, delta=>$h->{size}, kind=>'NEW' };
    } else {
        my $delta = $h->{size} - ($prev->{size}//0);
        if ($delta >= $MIN_FILE_GROWTH_BYTES) {
            push @events, { %$h, prev_size=>$prev->{size}, delta=>$delta, kind=>'GROWTH' };
        }
    }
}

# 5) TOP жирных директорий (всегда считаем независимо от событий)
my $top_dirs = [];
if ($DIR_TALLY_ENABLE) {
    my $pairs = tally_large_dirs(\@ROOT_DIRS, $DIR_TALLY_MAX_DEPTH, $DIR_TALLY_FILE_LIMIT);
    my @flt = grep { $_->[1] >= $DIR_TALLY_MIN_BYTES } @$pairs;
    if (@flt) {
        @flt = @flt[0 .. ($DIR_TALLY_TOP_N-1)] if @flt > $DIR_TALLY_TOP_N;
        $top_dirs = \@flt;
    }
}

# 6) Если нет событий и нет топ-папок — выходим тихо (для cron)
if (!@events && (!@$top_dirs)) { exit 0; }

# 7) Письмо
my $body = "";
$body .= "Large files on NFS (find-only, no du)\n";
$body .= "Time      : $utc_now\n";
$body .= "Host      : $hostname\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "MaxDepth  : $MAX_DEPTH (file search)\n";
if ($DIR_TALLY_ENABLE) {
    $body .= "DirTally  : depth=$DIR_TALLY_MAX_DEPTH, group_depth=$DIR_GROUP_DEPTH_FROM_ROOT, file_limit=$DIR_TALLY_FILE_LIMIT, min=".human_size($DIR_TALLY_MIN_BYTES)."\n";
}
$body .= "\n";

if (@events) {
    $body .= "EVENTS (NEW/GROWTH ≥ ".human_size($MIN_FILE_GROWTH_BYTES)."):\n";
    for my $e (@events) {
        my $hr = human_size($e->{size});
        my $delta_hr = defined $e->{delta} ? human_size($e->{delta}) : 'n/a';
        my $prev_hr  = defined $e->{prev_size} ? human_size($e->{prev_size}) : 'n/a';
        $body .= "[$e->{kind}] $e->{path}\n";
        $body .= "  Size     : $hr ($e->{size} bytes)\n";
        $body .= "  PrevSize : $prev_hr"; $body .= defined $e->{prev_size} ? " ($e->{prev_size} bytes)\n" : "\n";
        $body .= "  Δ         : $delta_hr"; $body .= defined $e->{delta} ? " ($e->{delta} bytes)\n" : "\n";
        $body .= "  Modified : ".format_time($e->{mtime})."\n";
        $body .= "----------------------------------------\n";
    }
    $body .= "\n";
}

if (@$top_dirs) {
    $body .= "TOP DIRECTORIES (>= ".human_size($DIR_TALLY_MIN_BYTES)."):\n";
    my $rank = 1;
    for my $pd (@$top_dirs) {
        my ($dir,$bytes) = @$pd;
        $body .= sprintf("  %2d) %s  %s (%d bytes)\n", $rank++, $dir, human_size($bytes), $bytes);
    }
    $body .= "\n";
}

my $subject  = "$SUBJECT_PREFIX on $hostname";
my $date_hdr = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email    = build_email_message(
    from        => $FROM, to_csv=>$RECIPIENTS,
    subject     => $subject, body_text=>$body, date_header=>$date_hdr,
);

if ($DEBUG_PREVIEW || $DRY_RUN) { 
    my $io = $PREVIEW_TO_STDERR ? *STDERR : *STDOUT;
    print $io "================= EMAIL PREVIEW BEGIN =================\n";
    print $io $email;
    print $io "================= EMAIL PREVIEW  END  =================\n";
}
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with $?";
}

# 8) Обновляем индекс: все файлы из @events
ensure_state_dir($STATE_DIR);
my $idx_changed = 0;
for my $e (@events) {
    my $k = file_key($e->{dev}, $e->{ino});
    my $old = $idx{$k};
    if (!$old || $old->{size} != $e->{size} || $old->{mtime} != $e->{mtime} || ($old->{path}//'') ne $e->{path}) {
        $idx{$k} = { size=>$e->{size}, mtime=>$e->{mtime}, path=>$e->{path} };
        $idx_changed = 1;
    }
}
save_file_index($STATE_FILE_INDEX, \%idx) if $idx_changed;
exit 0;
