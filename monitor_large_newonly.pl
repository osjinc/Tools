#!/usr/bin/env perl
# monitor_large_du_drilldown.pl
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Корневые каталоги (level 0)
my @ROOT_DIRS = (
    '/var/data',      # пример
    # '/mnt/storage',
);

# Глубины уровней (относительно корня):
# level 1 = "имена проектов", level 2 = "служебные папки"
my $PROJECT_LEVEL   = 1;
my $SERVICE_LEVEL   = 2;

# Порог «большого файла» (байт). Пример: 2 GiB.
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;

# Минимальный прирост папки (байт) для "выросла".
my $MIN_DELTA_BYTES = 50 * 1024 * 1024;  # 50 MiB

# Быстрый просмотр файлов внутри служебной папки без рекурсии (0)
# или на 1 уровень вглубь (1). 0 обычно достаточно.
my $QUICK_PEEK_MAX_DEPTH = 0;

# e-mail
my $RECIPIENTS     = 'ops@example.com,admin@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files in grown dirs';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# Состояние
my $STATE_DIR         = '/var/lib/monitor_large';
my $STATE_FILE_KEYS   = "$STATE_DIR/state_files.db";   # уже разосланные файлы (dev:ino:size:mtime)
my $STATE_DIR_SIZES   = "$STATE_DIR/dir_sizes.db";     # размеры каталогов: path|bytes

# Отладка / предпросмотр
my $DEBUG_PREVIEW     = 1;  # печатать письмо
my $DRY_RUN           = 0;  # 1 = не отправлять, только показать
my $PREVIEW_TO_STDERR = 1;  # предпросмотр в stderr
# =================== END CONFIG ===================

# ---------- Утилиты ----------
sub ensure_state_dir {
    my ($d)=@_; return if -d $d;
    make_path($d) or die "Failed to create $d: $!";
}

sub human_size {
    my ($bytes)=@_;
    my @u=qw(B K M G T P);
    my ($v,$i)=($bytes+0,0);
    while ($v>=1024 && $i<$#u){$v/=1024;$i++}
    return $i==0 ? sprintf("%d %s",$bytes,$u[$i]) : sprintf("%.2f %s",$v,$u[$i]);
}

sub format_time {
    my ($epoch)=@_;
    return defined $epoch ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($epoch)) : 'unknown';
}

# Чтение/запись размеров директорий
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
        my $b = $href->{$p}+0;
        print {$fh} "$p|$b\n";
    }
    close $fh;
}

# Чтение/дописание ключей файлов
sub load_file_state {
    my ($path)=@_;
    my %seen;
    if (-f $path){
        open my $fh,'<',$path or die "Failed to open $path: $!";
        while (my $line=<$fh>) { chomp $line; $seen{$line}=1 if $line ne '' }
        close $fh;
    }
    return \%seen;
}
sub append_file_keys {
    my ($path,$keys)=@_;
    return unless @$keys;
    open my $fh,'>>',$path or die "Failed to open $path: $!";
    flock($fh,LOCK_EX) or die "Failed to lock $path: $!";
    print {$fh} "$_\n" for @$keys;
    close $fh;
}

# «du -sb path» → байты (быстро и наглядно для роста папок)
sub du_size_bytes {
    my ($path)=@_;
    return 0 unless -d $path;
    my $out = `du -sb --apparent-size '$path' 2>/dev/null`;
    # Формат: "<bytes>\t<path>\n"
    if ($?==0 && $out =~ /^(\d+)/){ return $1+0 }
    return 0; # fallback
}

# Директории ровно на нужной глубине от корня
sub list_dirs_at_level {
    my ($roots,$target_level)=@_;
    my @ret;
    my @stack = map { [$_,0] } @$roots;
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next unless -d _;
        if ($lvl==$target_level){ push @ret,$d; next; }
        next if $lvl>$target_level;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            next unless -d $p;
            push @stack, [$p,$lvl+1];
        }
        closedir($dh);
    }
    return \@ret;
}

# Быстрый просмотр файлов в служебной папке на ограниченной глубине
sub service_dir_quick_peek {
    my ($root,$threshold,$max_depth)=@_;
    my @stack = ([$root,0]);
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            if (-d $p) {
                if ($lvl < $max_depth) { push @stack, [$p,$lvl+1]; }
                next;
            }
            next unless -f _;
            my @st = stat($p) or next;
            my $size = $st[7] // 0;
            if ($size > $threshold) { closedir($dh); return 1; }
        }
        closedir($dh);
    }
    return 0;
}

# Рекурсивный поиск больших файлов под поддеревом
sub scan_for_large_files {
    my ($roots,$threshold)=@_;
    my @hits;
    my @stack = map { [$_] } @$roots;
    while (my $fr = pop @stack) {
        my ($d)=@$fr;
        next unless -e $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            if (-d $p){ push @stack, [$p]; next; }
            next unless -f _;
            my @st = stat($p) or next;
            my ($dev,$ino,$size,$mtime,$ctime) = @st[0,1,7,9,10];
            next unless defined $size && $size > $threshold;
            push @hits, { path=>$p, dev=>$dev, ino=>$ino, size=>$size, mtime=>$mtime, ctime=>$ctime };
        }
        closedir($dh);
    }
    return \@hits;
}

sub file_key { my ($dev,$ino,$size,$mtime)=@_; return join(':',$dev,$ino,$size,$mtime); }

# Письмо
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

# ============== ОСНОВНОЙ ХОД ==============
ensure_state_dir($STATE_DIR);

my $hostname = do{ my $h=`hostname`; chomp $h; $h; };

# Состояния
my $prev_sizes = load_dir_sizes($STATE_DIR_SIZES);   # path => bytes
my %prev_sizes = %$prev_sizes;
my $seen_files = load_file_state($STATE_FILE_KEYS);  # key set
my %seen       = %$seen_files;

# Признак: первый запуск (нет базы размеров) → делаем "полное обнаружение"
my $FIRST_RUN = (scalar(keys %prev_sizes) == 0) ? 1 : 0;

# 1) Директории проектов (level 1)
my $project_dirs = list_dirs_at_level(\@ROOT_DIRS, $PROJECT_LEVEL);

# 2) Для каждого проекта — текущий размер, рост
my %curr_sizes;
my @grown_projects;  # [proj, prev, curr]
for my $proj (@$project_dirs) {
    my $sz = du_size_bytes($proj);
    $curr_sizes{$proj} = $sz;
    my $prev = $prev_sizes{$proj} // 0;
    if ($FIRST_RUN || ($sz > $prev && ($sz - $prev) >= $MIN_DELTA_BYTES)) {
        push @grown_projects, [$proj, $prev, $sz];
    }
}

# 3) Служебные папки (level 2) под выросшими проектами
my @service_dirs_all;
if ($FIRST_RUN) {
    # на первом запуске — берём ВСЕ служебные папки под ВСЕМИ проектами
    $service_dirs_all = list_dirs_at_level(\@{$project_dirs}, $SERVICE_LEVEL);
} else {
    my @grown_proj_paths = map { $_->[0] } @grown_projects;
    $service_dirs_all = list_dirs_at_level(\@grown_proj_paths, $SERVICE_LEVEL);
}

# 4) Отбор кандидатов для глубокого сканирования:
#   a) выросшие по du (prev->curr)
#   b) quick-peek нашёл файл > порога (даже без роста)
my @grown_services;   # [svc, prev, curr, delta]
my @candidates;       # пути служебных папок для глубокого сканирования

for my $svc (@$service_dirs_all) {
    my $sz = du_size_bytes($svc);
    $curr_sizes{$svc} = $sz;
    my $prev = $prev_sizes{$svc} // 0;

    my $grown = (!$FIRST_RUN && $sz > $prev && ($sz - $prev) >= $MIN_DELTA_BYTES) ? 1 : 0;
    my $peek  = service_dir_quick_peek($svc, $THRESHOLD_BYTES, $QUICK_PEEK_MAX_DEPTH);

    if ($FIRST_RUN || $grown || $peek) {
        push @candidates, $svc;
        push @grown_services, [$svc, $prev, $sz, ($sz-$prev)] if $grown;
    }
}

# Уникализация кандидатов
my %uniq; @candidates = grep { !$uniq{$_}++ } @candidates;

# 5) Глубокий поиск больших файлов только в кандидатах
my @all_hits;
if (@candidates) {
    my $hits = scan_for_large_files(\@candidates, $THRESHOLD_BYTES);
    push @all_hits, @$hits if $hits;
}

# 6) Фильтр «только новые»
my (@new_hits, @new_keys);
for my $h (@all_hits) {
    my $k = file_key(@{$h}{qw/dev ino size mtime/});
    next if $seen{$k};
    push @new_hits, $h;
    push @new_keys, $k;
}

# 7) Если ничего нового — обновить размеры и выйти
if (!@new_hits) {
    my %save = %prev_sizes;
    $save{$_} = $curr_sizes{$_} for keys %curr_sizes;
    save_dir_sizes($STATE_DIR_SIZES, \%save);
    exit 0;
}

# 8) Письмо
my $utc_now = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));
my $body = "";
$body .= "Large files report (NEW ONLY; growth + quick-peek; first_run=$FIRST_RUN)\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "Min delta : ".human_size($MIN_DELTA_BYTES)." ($MIN_DELTA_BYTES bytes)\n";
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

for my $h (@new_hits) {
    my $hr = human_size($h->{size});
    $body .= "File     : $h->{path}\n";
    $body .= "Size     : $hr ($h->{size} bytes)\n";
    $body .= "Modified : ".format_time($h->{mtime})."\n";
    $body .= "CTime    : ".format_time($h->{ctime})."\n";
    $body .= "Directory: ".($h->{path}=~m{^(.+)/[^/]+$} ? $1 : '.')."\n";
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

# 9) Предпросмотр / отправка
if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email, $PREVIEW_TO_STDERR); }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "Cannot open sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with status $?";
}

# 10) Обновить состояния
ensure_state_dir($STATE_DIR);
append_file_keys($STATE_FILE_KEYS, \@new_keys);
my %save = %prev_sizes;
$save{$_} = $curr_sizes{$_} for keys %curr_sizes;
save_dir_sizes($STATE_DIR_SIZES, \%save);

exit 0;
