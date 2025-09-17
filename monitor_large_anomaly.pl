#!/usr/bin/env perl
# monitor_large_anomaly.pl
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Корни (уровень 0)
my @ROOT_DIRS = (
    '/var/data',    # ← замените на ваш корень
);

# Уровни:
# level 1 = "имена проектов", level 2 = "служебные папки", ниже — файлы
my $PROJECT_LEVEL = 1;
my $SERVICE_LEVEL = 2;

# Порог "большого файла"
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;   # 2 GiB

# Аномалия по размеру папки = (size >= max(ABS_MIN, FACTOR * median_siblings))
# для уровня проектов:
my $PROJECT_ABS_MIN_BYTES = 10 * 1024 * 1024 * 1024;  # 10 GiB (настройте под себя)
my $PROJECT_FACTOR        = 1.8;                      # > медианы * 1.8

# для уровня служебных папок:
my $SERVICE_ABS_MIN_BYTES = 5 * 1024 * 1024 * 1024;   # 5 GiB
my $SERVICE_FACTOR        = 1.8;

# ограничители количества кандидатов (без фанатизма)
my $MAX_PROJECT_CANDIDATES = 5;
my $MAX_SERVICE_CANDIDATES = 10;

# Поведение с симлинками
my $SKIP_SYMLINKS = 1;

# ===== Email =====
my $RECIPIENTS     = 'ops@example.com,admin@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files (anomaly drilldown)';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# ===== Debug / Preview =====
my $DEBUG_PREVIEW     = 1;  # 1 = покажет письмо (заголовки+тело)
my $DRY_RUN           = 0;  # 1 = не отправлять, только предпросмотр
my $PREVIEW_TO_STDERR = 1;  # 1 = предпросмотр в stderr

# =================== END CONFIG ===================

# ---------------------- Утилиты ----------------------
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

sub ensure_dir { my ($d)=@_; return if -d $d; make_path($d) or die "create $d: $!"; }

# du -sb --apparent-size (быстро, сервер считает сам)
sub du_size_bytes {
    my ($path)=@_;
    return 0 unless -d $path;
    my $out = `du -sb --apparent-size '$path' 2>/dev/null`;
    if ($?==0 && $out =~ /^(\d+)/){ return $1+0 }
    return 0;
}

# список подкаталогов РОВНО на 1 уровень ниже указанного каталога
sub list_immediate_subdirs {
    my ($dir)=@_;
    my @subs;
    return \@subs unless -d $dir;
    opendir(my $dh,$dir) or return \@subs;
    while (defined(my $e=readdir($dh))) {
        next if $e eq '.' || $e eq '..';
        my $p = "$dir/$e";
        next if $SKIP_SYMLINKS && -l $p;
        push @subs, $p if -d $p;
    }
    closedir($dh);
    return \@subs;
}

# медиана массива чисел (0 для пустого)
sub median {
    my (@v) = @_;
    return 0 unless @v;
    @v = sort { $a <=> $b } @v;
    my $n = @v;
    return $v[int($n/2)] if $n % 2 == 1;
    return int( ($v[$n/2 - 1] + $v[$n/2]) / 2 );
}

# выбрать аномальные каталоги по правилу: size >= max(abs_min, factor*median)
sub pick_anomalies {
    my ($pairs_ref, $abs_min, $factor, $limit) = @_;
    # pairs: [ [path,size], ... ]
    my @pairs = @$pairs_ref;
    return [] unless @pairs;

    my @sizes = map { $_->[1] } @pairs;
    my $med   = median(@sizes);
    my $thr   = $med * $factor;
    $thr = $abs_min if $abs_min > $thr;

    # Если мало соседей (<=2), опираемся только на абсолютный минимум
    if (@pairs <= 2) { $thr = $abs_min; }

    my @an = grep { $_->[1] >= $thr } @pairs;

    # сортируем по размеру убыв. и режем до лимита
    @an = sort { $b->[1] <=> $a->[1] } @an;
    if ($limit && @an > $limit) { @an = @an[0..$limit-1]; }
    return \@an;
}

# глубокий скан ТОЛЬКО в заданных поддеревьях: найти файлы >= THRESHOLD_BYTES
sub scan_for_large_files {
    my ($roots_ref, $threshold) = @_;
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
            my $p = "$d/$e";
            if (-d $p) {
                next if $SKIP_SYMLINKS && -l $p;
                push @stack, [$p];
                next;
            }
            next unless -f _;
            my @st = stat($p) or next;
            my ($dev,$ino,$size,$mtime,$ctime) = @st[0,1,7,9,10];
            next unless defined $size && $size >= $threshold;
            push @hits, { path=>$p, size=>$size, mtime=>$mtime, ctime=>$ctime };
        }
        closedir($dh);
    }
    return \@hits;
}

# письмо
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

# ---------------------- ОСНОВНОЙ ХОД ----------------------
my $hostname = do{ my $h=`hostname`; chomp $h; $h; };
my $utc_now  = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));

# 0) По каждому корню: собрать пары [подкаталог_уровня1, размер]
my @project_pairs;  # [path,size]
for my $root (@ROOT_DIRS) {
    my $subs = list_immediate_subdirs($root);
    for my $proj (@$subs) {
        my $sz = du_size_bytes($proj);
        push @project_pairs, [$proj, $sz];
    }
}

# 1) Выбрать аномальные "проекты"
my $proj_an = pick_anomalies(\@project_pairs, $PROJECT_ABS_MIN_BYTES, $PROJECT_FACTOR, $MAX_PROJECT_CANDIDATES);

# Если нет аномалий на уровне проектов — выходим (ничего не сканируем глубоко)
if (!@$proj_an) {
    exit 0 unless ($DEBUG_PREVIEW || $DRY_RUN);
    # в режиме предпросмотра покажем диагностическую заметку
    my $note = "No anomalous project dirs at $utc_now on $hostname.\n";
    if ($PREVIEW_TO_STDERR) { print STDERR $note } else { print STDOUT $note }
    exit 0;
}

# 2) Для каждого аномального проекта — собрать пары [служебная_папка, размер]
my @service_pairs;  # [path,size]
for my $pair (@$proj_an) {
    my ($proj_path,$proj_sz) = @$pair;
    my $servs = list_immediate_subdirs($proj_path);
    for my $svc (@$servs) {
        my $sz = du_size_bytes($svc);
        push @service_pairs, [$svc, $sz];
    }
}

# 3) Выбрать аномальные "служебные" папки (кандидаты для детального поиска файлов)
my $svc_an = pick_anomalies(\@service_pairs, $SERVICE_ABS_MIN_BYTES, $SERVICE_FACTOR, $MAX_SERVICE_CANDIDATES);

# Если и здесь не нашли аномалий — дальше не идём
if (!@$svc_an) {
    exit 0 unless ($DEBUG_PREVIEW || $DRY_RUN);
    my $note = "No anomalous service dirs at $utc_now on $hostname.\n";
    if ($PREVIEW_TO_STDERR) { print STDERR $note } else { print STDOUT $note }
    exit 0;
}

# 4) Глубоко ищем большие файлы ТОЛЬКО в выбранных служебных папках
my @svc_paths = map { $_->[0] } @$svc_an;
my $hits = scan_for_large_files(\@svc_paths, $THRESHOLD_BYTES);

# Если нет больших файлов — тоже выходим молча (в cron это нормально)
if (!$hits || !@$hits) {
    exit 0 unless ($DEBUG_PREVIEW || $DRY_RUN);
    my $note = "No big files (>= ".human_size($THRESHOLD_BYTES).") in candidates at $utc_now.\n";
    if ($PREVIEW_TO_STDERR) { print STDERR $note } else { print STDOUT $note }
    exit 0;
}

# 5) Письмо (все найденные большие файлы в аномальных служебных папках)
my $body = "";
$body .= "Large files detected via anomaly drilldown\n";
$body .= "Scanned   : $utc_now (UTC)\n";
$body .= "Host      : $hostname\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n\n";

$body .= "ANOMALOUS PROJECT DIRS (top ".scalar(@$proj_an)."):\n";
for my $p (@$proj_an) {
    $body .= sprintf("  %s  %s\n", $p->[0], human_size($p->[1]));
}
$body .= "\nANOMALOUS SERVICE DIRS (top ".scalar(@$svc_an)."):\n";
for my $s (@$svc_an) {
    $body .= sprintf("  %s  %s\n", $s->[0], human_size($s->[1]));
}
$body .= "\nFILES >= ".human_size($THRESHOLD_BYTES).":\n";

for my $h (@$hits) {
    my $hr = human_size($h->{size});
    $body .= "File     : $h->{path}\n";
    $body .= "Size     : $hr ($h->{size} bytes)\n";
    $body .= "Modified : ".format_time($h->{mtime})."\n";
    $body .= "CTime    : ".format_time($h->{ctime})."\n";
    $body .= "Directory: ".($h->{path}=~m{^(.+)/[^/]+$} ? $1 : '.')."\n";
    $body .= "----------------------------------------\n";
}

my $subject  = "$SUBJECT_PREFIX on $hostname (threshold ".human_size($THRESHOLD_BYTES).")";
my $date_hdr = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email    = build_email_message(
    from        => $FROM,
    to_csv      => $RECIPIENTS,
    subject     => $subject,
    body_text   => $body,
    date_header => $date_hdr,
);

# 6) Предпросмотр / отправка
if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email, $PREVIEW_TO_STDERR); }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "Cannot open sendmail: $!";
    print $sm $email;
    close $sm or warn "sendmail exited with status $?";
}

# Тишина для cron
exit 0;
