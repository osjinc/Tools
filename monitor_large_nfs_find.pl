#!/usr/bin/env perl
# monitor_large_nfs_find.pl
# NFS-friendly: без du; поиск ТОЛЬКО больших файлов + кэш известных, "только новые/рост".
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

# Ограничение поиска (важно для NFS)
my $MAX_DEPTH         = 4;     # глубина обхода (0=только корень, 1=дети, …)
my $FOLLOW_SYMLINKS   = 0;     # 0 — не следовать симлинкам (безопаснее на NFS)
my $XDEV              = 0;     # 1 — не пересекать другие файловые системы (обычно для локальных, на NFS часто 0)

# Исключения (паттерны путей для -prune). Регэксп Perl, применяется к абсолютному пути.
my @EXCLUDE_DIR_PATTERNS = (
    qr{/\.(git|svn|hg)(/|$)},
    qr{/tmp(/|$)},
    # qr{/data/old_backups(/|$)},
);

# Email
my $RECIPIENTS     = 'ops@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files on NFS';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# Состояние (кэш известных крупных файлов)
my $STATE_DIR        = '/var/lib/monitor_large';
my $STATE_FILE_INDEX = "$STATE_DIR/file_index.db";  # строки: dev:ino|size|mtime|path

# Debug / Preview
my $DEBUG_PREVIEW     = 0;   # 1 — показать письмо
my $DRY_RUN           = 0;   # 1 — не отправлять
my $PREVIEW_TO_STDERR = 1;
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

# Фильтр по исключениям директорий
sub path_is_excluded {
    my ($path)=@_;
    for my $re (@EXCLUDE_DIR_PATTERNS) {
        return 1 if $path =~ $re;
    }
    return 0;
}

# Поиск больших файлов: легковесный GNU find (только метаданные)
# Возвращает массив хэшей: { path, size, mtime, ctime, dev, ino }
sub find_large_files {
    my ($roots_ref, $threshold, $maxdepth)=@_;
    my @roots = @$roots_ref;
    my @found;

    my $size_arg = $threshold . 'c';  # байты
    my $depth_arg = defined $maxdepth ? "-maxdepth $maxdepth" : "";

    # Строим команду find для каждого корня, применяя исключения как -path ... -prune
    for my $root (@roots) {
        next unless -d $root;

        # Соберём часть для -prune
        my @prunes;
        for my $re (@EXCLUDE_DIR_PATTERNS) {
            # переводим регэксп в простую подстроку, если получилось — иначе пропустим в шелл-части
            # лучше всего задать исключения сразу строками путей выше в конфиге
        }

        # Базовая команда (GNU find)
        # -ignore_readdir_race уменьшает ворнинги;
        # -type f -size +Nc — только файлы больше порога
        # -printf — выводим размер, mtime(sec), ctime(sec) и путь
        my @cmd = ('find', $root);
        push @cmd, ('-xdev') if $XDEV;
        push @cmd, (split(/\s+/, $depth_arg)) if $depth_arg;

        # Применим -prune к исключениям (в виде нескольких -path '...' -prune -o …)
        # Упростим: будем пропускать исключения на стороне Perl (быстрее и гибче),
        # а find просто найдёт кандидатов.

        push @cmd, ('-ignore_readdir_race', '-type', 'f', '-size', '+'.$size_arg,
                    '-printf', '%s\t%T@\t%C@\t%p\0');  # NUL-разделитель путей

        # Выполняем
        my $pid = open(my $fh, "-|", @cmd);
        if (!$pid) { warn "Cannot run find @cmd: $!"; next; }

        local $/ = "\0";
        while (defined(my $rec = <$fh>)) {
            chomp $rec;
            my ($sz,$mt,$ct,$path) = split(/\t/, $rec, 4);
            next unless defined $path;
            next if path_is_excluded($path);
            # stat для dev/ino (можно взять и из lstat)
            my @st = lstat($path);
            next unless @st;
            my ($dev,$ino) = @st[0,1];
            push @found, {
                path  => $path,
                size  => int($sz),
                mtime => int($mt),
                ctime => int($ct),
                dev   => $dev,
                ino   => $ino,
            };
        }
        close $fh;
    }

    return \@found;
}

# Письмо
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

# 1) Перечитываем кэш
my $idx_ref = load_file_index($STATE_FILE_INDEX); my %idx=%$idx_ref;

# 2) Проверяем уже известные крупные файлы (дёшево для NFS)
my @events;   # {path,size,mtime,ctime,prev_size?,delta?,kind}
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

# 3) Лёгкое обнаружение новых крупных файлов (ограниченная область поиска)
my $found = find_large_files(\@ROOT_DIRS, $THRESHOLD_BYTES, $MAX_DEPTH);

# 4) Отфильтровать только "NEW" (по dev:ino) и добавить "GROWTH" если нужно
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

# 5) Если событий нет — выходим тихо
exit 0 unless @events;

# 6) Письмо
my $body = "";
$body .= "Large files on NFS (find-only, no du)\n";
$body .= "Time      : $utc_now\n";
$body .= "Host      : $hostname\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "MaxDepth  : $MAX_DEPTH  (search bounds)\n\n";
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
    $body .= "  CTime    : ".format_time($e->{ctime})."\n";
    $body .= "----------------------------------------\n";
}

my $subject  = "$SUBJECT_PREFIX on $hostname";
my $date_hdr = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email    = build_email_message(
    from        => $FROM, to_csv=>$RECIPIENTS,
    subject     => $subject, body_text=>$body, date_header=>$date_hdr,
);

if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email,$PREVIEW_TO_STDERR) }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with $?";
}

# 7) Обновляем индекс: все файлы из @events
ensure_state_dir($STATE_DIR);
for my $e (@events) {
    my $k = file_key($e->{dev}, $e->{ino});
    $idx{$k} = { size=>$e->{size}, mtime=>$e->{mtime}, path=>$e->{path} };
}
save_file_index($STATE_FILE_INDEX, \%idx);
exit 0;
