#!/usr/bin/env perl
# monitor_large_anomaly.pl
# Универсальный "точечный" монитор:
# /ROOT/*  -> проекты (level 1)
# /ROOT/*/* -> служебные папки (level 2, любые имена)
# Шаги: du проектов -> выбираем аномальные/крупные -> du служебных -> выбираем кандидатов
# -> deep scan ТОЛЬКО в кандидатах -> письма только NEW/GROWTH по (dev:ino)
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Корневые директории (уровень 0)
my @ROOT_DIRS = (
    '/data',       # ← замените под себя
);

# Уровни: 1 = проекты, 2 = служебные
my $PROJECT_LEVEL = 1;
my $SERVICE_LEVEL = 2;

# Порог "большого файла"
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;    # 2 GiB

# Считать повторно только при росте файла на ≥ столько (1 = любое увеличение)
my $MIN_FILE_GROWTH_BYTES = 1;

# Аномалия по размеру папки (медиана * коэффициент) и абсолютный минимум
# Для проектов:
my $PROJECT_ABS_MIN_BYTES = 0;    # 0 = отключить абсолютный минимум
my $PROJECT_FACTOR        = 1.8;  # множитель к медиане
my $MAX_PROJECT_CAND      = 20;   # ограничение числа проектов-кандидатов

# Для служебных:
my $SERVICE_ABS_MIN_BYTES = 0;
my $SERVICE_FACTOR        = 1.8;
my $MAX_SERVICE_CAND      = 40;

# Быстрый "peek" внутри служебной папки: глубина 0..N
my $QUICK_PEEK_MAX_DEPTH  = 2;

# Пропускать симлинки
my $SKIP_SYMLINKS         = 1;

# ===== Email =====
my $RECIPIENTS     = 'ops@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files in service dirs';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# ===== State (для «только новые/рост») =====
my $STATE_DIR        = '/var/lib/monitor_large';
my $STATE_FILE_INDEX = "$STATE_DIR/file_index.db";   # строки: dev:ino|size|mtime

# ===== Debug / Preview =====
my $DEBUG_PREVIEW     = 0;   # 1 = показать письмо (заголовки+тело)
my $DRY_RUN           = 0;   # 1 = не отправлять письмо
my $PREVIEW_TO_STDERR = 1;   # вывод предпросмотра в STDERR
# =================== END CONFIG =====================

# ---------------------- УТИЛИТЫ ----------------------
sub ensure_state_dir { my ($d)=@_; return if -d $d; make_path($d) or die "create $d: $!" }

sub human_size {
    my ($bytes)=@_;
    my @u=qw(B K M G T P);
    my ($v,$i)=($bytes+0,0);
    while ($v>=1024 && $i<$#u){ $v/=1024; $i++ }
    return $i==0 ? sprintf("%d %s",$bytes,$u[$i]) : sprintf("%.2f %s",$v,$u[$i]);
}

sub format_time { my ($epoch)=@_; return defined $epoch ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($epoch)) : 'unknown' }

# du -sb --apparent-size (быстро, считает ОС)
sub du_size_bytes {
    my ($path)=@_;
    return 0 unless -d $path;
    my $q=$path; $q=~s/"/\\"/g;
    my $out = qx(du -sb --apparent-size "$q" 2>/dev/null);
    return ($?==0 && $out =~ /^(\d+)/) ? $1+0 : 0;
}

# Подкаталоги РОВНО на 1 уровень ниже
sub list_immediate_subdirs {
    my ($dir)=@_;
    my @subs;
    return \@subs unless -d $dir;
    opendir(my $dh,$dir) or return \@subs;
    while (defined(my $e=readdir($dh))) {
        next if $e eq '.' || $e eq '..';
        my $p="$dir/$e";
        next if $SKIP_SYMLINKS && -l $p;
        push @subs, $p if -d $p;
    }
    closedir($dh);
    return \@subs;
}

# Медиана
sub median {
    my (@v)=@_;
    return 0 unless @v;
    @v = sort { $a <=> $b } @v;
    my $n = @v;
    return $v[int($n/2)] if $n % 2;
    return int(($v[$n/2 - 1] + $v[$n/2]) / 2);
}

# Выбор аномалий среди пар [path,size] + обязательное: size >= THRESHOLD_BYTES
sub pick_anomalies_with_threshold {
    my ($pairs_ref,$abs_min,$factor,$limit,$file_threshold)=@_;
    my @pairs = @$pairs_ref;
    return [] unless @pairs;

    my @sizes = map { $_->[1] } @pairs;
    my $med   = median(@sizes);
    my $thr   = (@pairs <= 2) ? 0 : $med * $factor;  # мало соседей — медиана не информативна
    $thr = $abs_min if $abs_min > $thr;

    # Кандидат, если: аномалия ИЛИ размер ≥ порога большого файла
    my @an = grep { $_->[1] >= $thr || $_->[1] >= $file_threshold } @pairs;

    @an = sort { $b->[1] <=> $a->[1] } @an;
    @an = @an[0..$limit-1] if $limit && @an > $limit;
    return \@an;
}

# Ограниченный быстрый просмотр: если сразу видим файл ≥ порога — триггерим папку
sub quick_peek_large_file {
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
                push @stack, [$p,$lvl+1] if $lvl < $max_depth;
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

# Рекурсивный поиск файлов ≥ порога (только в выбранных поддеревьях)
sub deep_find_large_files {
    my ($roots_ref,$threshold)=@_;
    my @roots = @$roots_ref;
    my @hits;
    my @stack = map { [$_] } @roots;
    while (my $fr = pop @stack) {
        my ($d)=@$fr;
        next unless -e $d;
        next if $SKIP_SYMLINKS && -l $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p="$d/$e";
            if (-d $p) {
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

# --- Индекс файлов (dev:ino -> {size,mtime}) ---
sub load_file_index {
    my ($path)=@_;
    my %idx;
    if (-f $path) {
        open my $fh,'<',$path or die "open $path: $!";
        while (my $l=<$fh>) {
            chomp $l; next unless $l;
            my ($k,$s,$m) = split(/\|/,$l,3);
            $idx{$k} = { size=>($s||0)+0, mtime=>($m||0)+0 };
        }
        close $fh;
    }
    return \%idx;
}
sub save_file_index {
    my ($path,$h)=@_;
    open my $fh,'>',$path or die "write $path: $!";
    flock($fh,LOCK_EX) or die "lock $path: $!";
    for my $k (keys %$h) {
        printf {$fh} "%s|%d|%d\n", $k, $h->{$k}{size}+0, $h->{$k}{mtime}+0;
    }
    close $fh;
}
sub file_key { my ($dev,$ino)=@_; return "$dev:$ino" }

# --- email ---
sub build_email_message {
    my (%a)=@_;
    my ($from,$to,$subj,$body,$date)=@a{qw/from to_csv subject body_text date_header/};
    $to//= ''; $to=~s/\s+//g; $to=~s/,/, /g;
    return "From: $from\nTo: $to\nSubject: $subj\nDate: $date\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\n$body";
}
sub preview_print { my ($t,$err)=@_; my $io=$err?*STDERR:*STDOUT; print $io "================= EMAIL PREVIEW BEGIN =================\n$t\n================= EMAIL PREVIEW  END  =================\n" }

# ===================== MAIN =====================
ensure_state_dir($STATE_DIR);
my $hostname = do{ my $h=`hostname`; chomp $h; $h; };
my $utc_now  = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));

# 1) ПРОЕКТЫ (level 1) под всеми корнями
my @proj_pairs;  # [path,size]
for my $root (@ROOT_DIRS) {
    my $subs = list_immediate_subdirs($root);
    for my $proj (@$subs) {
        my $sz = du_size_bytes($proj);
        push @proj_pairs, [$proj,$sz];
    }
}
my $proj_cand = pick_anomalies_with_threshold(
    \@proj_pairs, $PROJECT_ABS_MIN_BYTES, $PROJECT_FACTOR, $MAX_PROJECT_CAND, $THRESHOLD_BYTES
);
exit 0 unless @$proj_cand;  # нет подозрительных проектов — не углубляемся

# 2) СЛУЖЕБНЫЕ ПАПКИ (level 2) — любые имена (все дети выбранных проектов)
my @svc_pairs;   # [path,size]
for my $pp (@$proj_cand) {
    my ($proj_path,$proj_sz)=@$pp;
    my $servs = list_immediate_subdirs($proj_path);
    for my $svc (@$servs) {
        # только каталоги второго уровня (прямые дети проекта)
        my $sz = du_size_bytes($svc);
        push @svc_pairs, [$svc,$sz];
    }
}

# кандидаты-служебные: аномалия ИЛИ размер ≥ порога файла
my $svc_cand = pick_anomalies_with_threshold(
    \@svc_pairs, $SERVICE_ABS_MIN_BYTES, $SERVICE_FACTOR, $MAX_SERVICE_CAND, $THRESHOLD_BYTES
);

# добавим quick-peek: если в служебной уже лежит крупный файл где-то внутри (до N уровней) — включаем
my %svc_hash = map { $_->[0] => 1 } @$svc_cand;
for my $sp (@svc_pairs) {
    my ($svc_path,$svc_sz) = @$sp;
    next if $svc_hash{$svc_path};
    if (quick_peek_large_file($svc_path,$THRESHOLD_BYTES,$QUICK_PEEK_MAX_DEPTH)) {
        push @$svc_cand, [$svc_path,$svc_sz];
        $svc_hash{$svc_path} = 1;
    }
}
exit 0 unless @$svc_cand;

# 3) Глубокий поиск больших файлов только в кандидатах
my @svc_paths = map { $_->[0] } @$svc_cand;
my $hits = deep_find_large_files(\@svc_paths, $THRESHOLD_BYTES);
exit 0 unless ($hits && @$hits);

# 4) «Только новые/рост»
my $idx_ref = load_file_index($STATE_FILE_INDEX); my %idx=%$idx_ref;
my @events;  # {path,size,mtime,ctime,prev_size?,delta?,kind}
for my $h (@$hits) {
    my $k = file_key($h->{dev},$h->{ino});
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
exit 0 unless @events;

# 5) Письмо
my $body = "";
$body .= "Large files detected (universal service-dirs)\n";
$body .= "Time      : $utc_now (UTC)\n";
$body .= "Host      : $hostname\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n\n";

$body .= "PROJECT CANDIDATES:\n";
for my $p (@$proj_cand) { $body .= sprintf("  %s  %s\n", $p->[0], human_size($p->[1])); }

$body .= "\nSERVICE CANDIDATES:\n";
for my $s (@$svc_cand) { $body .= sprintf("  %s  %s\n", $s->[0], human_size($s->[1])); }

$body .= "\nEVENTS (NEW/GROWTH ≥ ".human_size($MIN_FILE_GROWTH_BYTES)."):\n";
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
    $body .= "  Directory: ".($e->{path}=~m{^(.+)/[^/]+$} ? $1 : '.')."\n";
    $body .= "----------------------------------------\n";
}

my $subject  = "$SUBJECT_PREFIX on $hostname";
my $date_hdr = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email    = build_email_message(
    from        => $FROM, to_csv=>$RECIPIENTS,
    subject     => $subject, body_text=>$body, date_header=>$date_hdr,
);

if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email, $PREVIEW_TO_STDERR); }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "Cannot open sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with status $?";
}

# 6) Обновить индекс уведомлённых файлов
ensure_state_dir($STATE_DIR);
for my $e (@events) {
    my $k = file_key($e->{dev},$e->{ino});
    $idx{$k} = { size=>$e->{size}, mtime=>$e->{mtime} };
}
save_file_index($STATE_FILE_INDEX, \%idx);

exit 0;
