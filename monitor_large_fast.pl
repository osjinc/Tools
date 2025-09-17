#!/usr/bin/env perl
# monitor_large_fast.pl
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Корни (level 0)
my @ROOT_DIRS = (
    '/rskjf',   # пример: поменяйте под себя
);

# Глубины уровней относительно корня:
# level 1 = "имена проектов", level 2 = "служебные папки"
my $PROJECT_LEVEL = 1;
my $SERVICE_LEVEL = 2;

# Порог "большого файла" (байт). Пример: 2 GiB.
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;

# Минимальный прирост размера ПАПКИ (байт), чтобы считать её "выросшей"
# и углубляться в неё (ограничивает шум от мелких изменений).
my $MIN_DIR_DELTA_BYTES = 50 * 1024 * 1024;   # 50 MiB

# Минимальный прирост РАЗМЕРА ФАЙЛА (байт), чтобы считать рост "значимым"
# при повторных уведомлениях. 1 => любое увеличение.
my $MIN_FILE_GROWTH_BYTES = 1;

# Быстрый "подглядыватель": заглядываем в служебные папки
# максимум на указанную глубину (0 — только верхний уровень папки).
# Если сразу видим файл >= THRESHOLD_BYTES — включаем папку в кандидаты,
# даже если папка не росла.
my $QUICK_PEEK_MAX_DEPTH = 1;

# Пропускать симлинки (1 = да)
my $SKIP_SYMLINKS = 1;

# ===== Email =====
my $RECIPIENTS     = 'ops@example.com,admin@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files detected';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# ===== State =====
my $STATE_DIR           = '/var/lib/monitor_large';
my $STATE_DIR_SIZES     = "$STATE_DIR/dir_sizes.db";   # "path|bytes"
my $STATE_FILE_INDEX    = "$STATE_DIR/file_index.db";  # "dev:ino|size|mtime" (последний УВЕДОМЛЁННЫЙ)

# ===== Debug / Preview =====
my $DEBUG_PREVIEW     = 0;  # 1 = показать письмо (заголовки+тело)
my $DRY_RUN           = 0;  # 1 = не отправлять, только предпросмотр
my $PREVIEW_TO_STDERR = 1;  # 1 = предпросмотр в stderr
# =================== END CONFIG ===================


# ---------------------- Утилиты ----------------------
sub ensure_state_dir {
    my ($d)=@_; return if -d $d;
    make_path($d) or die "Failed to create $d: $!";
}

sub human_size {
    my ($bytes)=@_;
    my @u=qw(B K M G T P);
    my ($v,$i)=($bytes+0,0);
    while ($v>=1024 && $i<$#u){ $v/=1024; $i++ }
    return $i==0 ? sprintf("%d %s",$bytes,$u[$i]) : sprintf("%.2f %s",$v,$u[$i]);
}

sub format_time {
    my ($epoch)=@_;
    return defined $epoch ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($epoch)) : 'unknown';
}

sub list_dirs_at_level {
    my ($roots,$target_level)=@_;
    my @ret;
    my @stack = map { [$_,0] } @$roots;
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next if $SKIP_SYMLINKS && -l $d;
        next unless -d _;
        if ($lvl==$target_level){ push @ret,$d; next; }
        next if $lvl>$target_level;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            next if $SKIP_SYMLINKS && -l $p;
            next unless -d $p;
            push @stack, [$p,$lvl+1];
        }
        closedir($dh);
    }
    return \@ret;
}

# du -sb --apparent-size: быстро считает логический размер каталога
sub du_size_bytes {
    my ($path)=@_;
    return 0 unless -d $path;
    my $out = `du -sb --apparent-size '$path' 2>/dev/null`;
    if ($?==0 && $out =~ /^(\d+)/){ return $1+0 }
    return 0;
}

# Быстрый взгляд на ограниченной глубине: если находим файл >= порога — триггерим папку
sub service_dir_quick_peek {
    my ($root,$threshold,$max_depth)=@_;
    my @stack = ([$root,0]);
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next if $SKIP_SYMLINKS && -l $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            if (-d $p) {
                next if $SKIP_SYMLINKS && -l $p;
                if ($lvl < $max_depth) { push @stack, [$p,$lvl+1]; }
                next;
            }
            next unless -f _;
            my @st = stat($p) or next;
            my $size = $st[7] // 0;
            if ($size >= $threshold) { closedir($dh); return 1; }
        }
        closedir($dh);
    }
    return 0;
}

# Глубокий скан кандидатов на большие файлы
sub scan_for_large_files {
    my ($roots,$threshold)=@_;
    my @hits;
    my @stack = map { [$_] } @$roots;
    while (my $fr = pop @stack) {
        my ($d)=@$fr;
        next unless -e $d;
        next if $SKIP_SYMLINKS && -l $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            if (-d $p){
                next if $SKIP_SYMLINKS && -l $p;
                push @stack, [$p];
                next;
            }
            next unless -f _;
            my @st = stat($p) or next;
            my ($dev,$ino,$size,$mtime,$ctime) = @st[0,1,7,9,10];
            next unless defined $size && $size >= $threshold;
            push @hits, { path=>$p, dev=>$dev, ino=>$ino, size=>$size, mtime=>$mtime, ctime=>$ctime };
        }
        closedir($dh);
    }
    return \@hits;
}

# --------- Состояние: размеры папок ---------
sub load_dir_sizes {
    my ($path)=@_;
    my %m;
    if (-f $path) {
        open my $fh,'<',$path or die "Failed to open $path: $!";
        while (my $line=<$fh>) {
            chomp $line; next unless $line;
            my ($p,$b)=split(/\|/,$line,2);
            $m{$p}=($b||0)+0;
        }
        close $fh;
    }
    return \%m;
}
sub save_dir_sizes {
    my ($path,$href)=@_;
    open my $fh,'>',$path or die "Failed to write $path: $!";
    flock($fh,LOCK_EX) or die "Failed to lock $path: $!";
    for my $p (sort keys %$href) {
        printf {$fh} "%s|%d\n", $p, $href->{$p}+0;
    }
    close $fh;
}

# --------- Состояние: индекс файлов (последнее УВЕДОМЛЕНИЕ) ---------
# Формат: "dev:ino|size|mtime"
sub load_file_index {
    my ($path)=@_;
    my %idx;
    if (-f $path) {
        open my $fh,'<',$path or die "Failed to open $path: $!";
        while (my $line=<$fh>) {
            chomp $line; next unless $line;
            my ($k,$s,$m) = split(/\|/,$line,3);
            $idx{$k} = { size=>($s||0)+0, mtime=>($m||0)+0 };
        }
        close $fh;
    }
    return \%idx;
}
sub save_file_index {
    my ($path,$href)=@_;
    open my $fh,'>',$path or die "Failed to write $path: $!";
    flock($fh,LOCK_EX) or die "Failed to lock $path: $!";
    for my $k (keys %$href) {
        my $r = $href->{$k};
        printf {$fh} "%s|%d|%d\n", $k, $r->{size}+0, $r->{mtime}+0;
    }
    close $fh;
}

sub file_key { my ($dev,$ino)=@_; return "$dev:$ino"; }

# --------- Письмо ---------
sub build_email_message {
    my (%a)=@_;
    my ($from,$to_csv,$subject,$body,$date) = @a{qw/from to_csv subject body_text date_header/};
    my $to=$to_csv//''; $to=~s/\s+//g; $to=~s/,/, /g;
    my $hdr="";
    $hdr.="From: $from\n";
    $hdr.="To: $to\n";
    $hdr.="Subject: $subject\n";
    $hdr.="Date: $date\n";
    $hdr.="MIME-Version: 1.0\n";
    $hdr.="Content-Type: text/plain; charset=UTF-8\n\n";
    return $hdr.$body;
}
sub preview_print {
    my ($text,$to_stderr)=@_;
    my $io = $to_stderr ? *STDERR : *STDOUT;
    print $io "================= EMAIL PREVIEW BEGIN =================\n";
    print $io $text;
    print $io "\n================= EMAIL PREVIEW  END  =================\n";
}


# ===================== ОСНОВНОЙ ХОД =====================
ensure_state_dir($STATE_DIR);

my $hostname = do{ my $h=`hostname`; chomp $h; $h; };

# Состояния
my $prev_sizes_ref = load_dir_sizes($STATE_DIR_SIZES);    # path => bytes
my %prev_sizes     = %$prev_sizes_ref;
my $file_idx_ref   = load_file_index($STATE_FILE_INDEX);  # dev:ino => {size,mtime}
my %file_idx       = %$file_idx_ref;

my $FIRST_RUN = (scalar(keys %prev_sizes) == 0) ? 1 : 0;

# 1) Проекты (level 1) и их текущие размеры
my $project_dirs = list_dirs_at_level(\@ROOT_DIRS, $PROJECT_LEVEL);
my %curr_sizes;
my @grown_projects;   # [proj, prev, curr]

for my $proj (@$project_dirs) {
    my $sz = du_size_bytes($proj);
    $curr_sizes{$proj} = $sz;
    my $prev = $prev_sizes{$proj} // 0;
    if ($FIRST_RUN || ($sz > $prev && ($sz - $prev) >= $MIN_DIR_DELTA_BYTES)) {
        push @grown_projects, [$proj, $prev, $sz];
    }
}

# 2) Служебные папки (level 2)
#   - первый запуск: все под всеми проектами
#   - иначе: все под "выросшими" проектами
my $service_dirs_all;
if ($FIRST_RUN) {
    $service_dirs_all = list_dirs_at_level($project_dirs, $SERVICE_LEVEL);
} else {
    my @grown_proj_paths = map { $_->[0] } @grown_projects;
    $service_dirs_all = list_dirs_at_level(\@grown_proj_paths, $SERVICE_LEVEL);
}

# 3) Кандидаты для глубокого сканирования:
#   a) Выросшие по du (prev->curr) — на уровне СЛУЖЕБНЫХ папок
#   b) Quick-peek по ВСЕМ служебным папкам (даже из проектов без роста)
my @candidates;
my @grown_services;   # [svc, prev, curr, delta]

# a) рост по du у служебных (считаем только для уже выбранных проектов, чтобы не грузить всё дерево)
for my $svc (@$service_dirs_all) {
    my $sz = du_size_bytes($svc);
    $curr_sizes{$svc} = $sz;
    my $prev = $prev_sizes{$svc} // 0;
    if ($FIRST_RUN || ($sz > $prev && ($sz - $prev) >= $MIN_DIR_DELTA_BYTES)) {
        push @candidates, $svc;
        push @grown_services, [$svc, $prev, $sz, ($sz-$prev)];
    }
}

# b) quick-peek по всем служебным папкам (включая те, чьи проекты не росли)
my $all_service_dirs = list_dirs_at_level($project_dirs, $SERVICE_LEVEL);
for my $svc (@$all_service_dirs) {
    next if grep { $_ eq $svc } @candidates;  # уже есть
    if (service_dir_quick_peek($svc, $THRESHOLD_BYTES, $QUICK_PEEK_MAX_DEPTH)) {
        push @candidates, $svc;
    }
}

# Уникализируем
my %uniq_c; @candidates = grep { !$uniq_c{$_}++ } @candidates;

# 4) Глубокий поиск больших файлов только в кандидатах
my @all_hits;
if (@candidates) {
    my $hits = scan_for_large_files(\@candidates, $THRESHOLD_BYTES);
    push @all_hits, @$hits if $hits;
}

# 5) Фильтрация событий: "новые" или "существенно выросшие"
my @events;  # { path, size, mtime, ctime, prev_size?, delta?, kind=>"NEW"|"GROWTH" }
for my $h (@all_hits) {
    my $k = file_key($h->{dev}, $h->{ino});
    my $prev = $file_idx{$k};  # {size,mtime} или undef
    if (!$prev) {
        # Никогда не уведомляли про этот (dev:ino) — это NEW
        push @events, { %$h, prev_size=>undef, delta=>$h->{size}, kind=>"NEW" };
    } else {
        my $delta = $h->{size} - ($prev->{size} // 0);
        if ($delta >= $MIN_FILE_GROWTH_BYTES) {
            push @events, { %$h, prev_size=>$prev->{size}, delta=>$delta, kind=>"GROWTH" };
        }
        # если delta < порога — молчим, чтобы не спамить
    }
}

# 6) Если событий нет — просто обновим размеры папок и выйдем
if (!@events) {
    my %save = %prev_sizes;
    $save{$_} = $curr_sizes{$_} for keys %curr_sizes;
    save_dir_sizes($STATE_DIR_SIZES, \%save);
    # Тишина (никакого stdout) — удобно для cron
    exit 0;
}

# 7) Сформировать письмо
my $utc_now = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));
my $body = "";
$body .= "Large files report (NEW or GROWTH >= ".human_size($MIN_FILE_GROWTH_BYTES).")\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "Dir delta : >= ".human_size($MIN_DIR_DELTA_BYTES)." ($MIN_DIR_DELTA_BYTES bytes)\n";
$body .= "Scanned   : $utc_now (UTC)\n";
$body .= "Host      : $hostname\n";
$body .= "Roots     : ".join(', ', @ROOT_DIRS)."\n";
$body .= "Candidates: ".scalar(@candidates)." service folder(s)\n\n";

if (@grown_projects) {
    $body .= "GROWN PROJECTS:\n";
    for my $g (@grown_projects) {
        my ($p,$pr,$cu)=@$g;
        $body .= sprintf("  %s: %s -> %s (Δ %s)\n",
            $p, human_size($pr), human_size($cu), human_size($cu-$pr));
    }
    $body .= "\n";
}
if (@grown_services) {
    $body .= "GROWN SERVICE DIRS:\n";
    for my $s (@grown_services) {
        my ($d,$pr,$cu,$dl)=@$s;
        $body .= sprintf("  %s: %s -> %s (Δ %s)\n",
            $d, human_size($pr), human_size($cu), human_size($dl));
    }
    $body .= "\n";
}

for my $e (@events) {
    my $hr = human_size($e->{size});
    my $delta_hr = defined $e->{delta} ? human_size($e->{delta}) : 'n/a';
    my $prev_hr  = defined $e->{prev_size} ? human_size($e->{prev_size}) : 'n/a';
    $body .= "[$e->{kind}] $e->{path}\n";
    $body .= "  Size     : $hr ($e->{size} bytes)\n";
    $body .= "  PrevSize : $prev_hr";
    $body .= defined $e->{prev_size} ? " ($e->{prev_size} bytes)\n" : "\n";
    $body .= "  Δ         : $delta_hr";
    $body .= defined $e->{delta} ? " ($e->{delta} bytes)\n" : "\n";
    $body .= "  Modified : ".format_time($e->{mtime})."\n";
    $body .= "  CTime    : ".format_time($e->{ctime})."\n";
    $body .= "  Directory: ".($e->{path}=~m{^(.+)/[^/]+$} ? $1 : '.')."\n";
    $body .= "----------------------------------------\n";
}

my $subject  = "$SUBJECT_PREFIX (threshold ".human_size($THRESHOLD_BYTES).") on $hostname";
my $date_hdr = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email    = build_email_message(
    from        => $FROM,
    to_csv      => $RECIPIENTS,
    subject     => $subject,
    body_text   => $body,
    date_header => $date_hdr,
);

# 8) Предпросмотр / отправка
if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email, $PREVIEW_TO_STDERR); }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "Cannot open sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with status $?";
}

# 9) Обновить состояния:
#   - записи размеров папок
#   - индекс файлов (только для тех, о ком УВЕДОМИЛИ: фиксируем их текущее size/mtime)
my %save_sizes = %prev_sizes;
$save_sizes{$_} = $curr_sizes{$_} for keys %curr_sizes;
save_dir_sizes($STATE_DIR_SIZES, \%save_sizes);

for my $e (@events) {
    my $k = file_key($e->{dev}, $e->{ino});
    $file_idx{$k} = { size=>$e->{size}, mtime=>$e->{mtime} };
}
save_file_index($STATE_FILE_INDEX, \%file_idx);

# Тишина для cron
exit 0;
