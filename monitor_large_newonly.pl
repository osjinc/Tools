#!/usr/bin/env perl
# monitor_large_staged.pl
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);

# ===================== CONFIG =====================
# Порог размера (в байтах). Пример: 2*1024*1024*1024 = 2 GiB
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;

# Дерево: корни -> проекты (depth 1) -> служебные (depth 2) -> файлы (глубже)
my @ROOT_DIRS = (
    '/var/data',
    # '/mnt/storage',
);

# e-mail
my $RECIPIENTS     = 'ops@example.com,admin@example.com';
my $FROM           = 'monitor@localhost';
my $SUBJECT_PREFIX = 'ALERT: large files found';
my $SENDMAIL_BIN   = '/usr/sbin/sendmail';

# Файлы состояния
my $STATE_DIR           = '/var/lib/monitor_large';
my $STATE_FILE_KEYS     = "$STATE_DIR/state_files.db";   # dev:ino:size:mtime
my $STATE_DIR_INFO      = "$STATE_DIR/dir_state.db";     # path|mtime|hot
my $HOT_TTL_RUNS        = 0;  # 0 = не гасим hot; >0 = через N "пустых" запусков снимаем hot

# Границы уровней
my $PROJECT_LEVEL = 1;  # глубина проектов относительно корня
my $SERVICE_LEVEL = 2;  # глубина "служебных" папок

# Отладка / предпросмотр
my $DEBUG_PREVIEW     = 1;  # печатать письмо
my $DRY_RUN           = 0;  # 1 = не отправлять, только показать
my $PREVIEW_TO_STDERR = 1;  # предпросмотр в stderr

# Нагрузочные подсказки (необязательно): nice/ionice лучше указывать в crontab, не здесь
# =================== END CONFIG ===================

# --------- Утилиты ---------
sub ensure_state_dir {
    my ($dir) = @_;
    return if -d $dir;
    make_path($dir) or die "Failed to create state dir $dir: $!";
}

sub human_size {
    my ($bytes) = @_;
    my @u = ('B','K','M','G','T','P');
    my ($v,$i) = ($bytes+0, 0);
    while ($v >= 1024 && $i < $#u) { $v/=1024; $i++; }
    return $i==0 ? sprintf("%d %s",$bytes,$u[$i]) : sprintf("%.2f %s",$v,$u[$i]);
}

sub format_time {
    my ($epoch) = @_;
    return defined $epoch ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($epoch)) : 'unknown';
}

# --------- Состояние: файлы ---------
sub load_file_state {
    my ($path) = @_;
    my %seen;
    if (-f $path) {
        open my $fh, '<', $path or die "Failed to open $path: $!";
        while (my $line = <$fh>) { chomp $line; $seen{$line}=1 if $line ne ''; }
        close $fh;
    }
    return \%seen;
}
sub append_file_keys {
    my ($path,$keys)=@_;
    return unless @$keys;
    open my $fh, '>>', $path or die "Failed to open $path: $!";
    flock($fh, LOCK_EX) or die "Failed to lock $path: $!";
    print {$fh} "$_\n" for @$keys;
    close $fh;
}

# --------- Состояние: каталоги (mtime + hot + ttl) ---------
# Формат: path|mtime|hot|ttl
sub load_dir_state {
    my ($path) = @_;
    my %m;
    if (-f $path) {
        open my $fh, '<', $path or die "Failed to open $path: $!";
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line;
            my ($p,$mt,$hot,$ttl) = split(/\|/,$line,4);
            $m{$p} = { mtime=>($mt||0), hot=>($hot||0), ttl=>defined $ttl ? $ttl+0 : 0 };
        }
        close $fh;
    }
    return \%m;
}
sub save_dir_state {
    my ($path,$href)=@_;
    open my $fh, '>', $path or die "Failed to write $path: $!";
    flock($fh, LOCK_EX) or die "Failed to lock $path: $!";
    for my $p (sort keys %$href) {
        my $r = $href->{$p};
        my $mt  = $r->{mtime} // 0;
        my $hot = $r->{hot}   // 0;
        my $ttl = $r->{ttl}   // 0;
        print {$fh} "$p|$mt|$hot|$ttl\n";
    }
    close $fh;
}

# --------- Быстрый обход до заданной глубины ---------
sub list_dirs_to_level {
    my ($roots,$target_level) = @_;
    my @dirs; # [path,level]
    my @stack = map { [$_,0] } @$roots;
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next unless -d _;
        push @dirs, [$d,$lvl];
        next if $lvl >= $target_level;
        opendir(my $dh,$d) or next;
        while (defined(my $e = readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p = "$d/$e";
            next unless -d $p;
            push @stack, [$p,$lvl+1];
        }
        closedir($dh);
    }
    return \@dirs;
}

# --------- Полный скан выбранных поддеревьев (поиск больших файлов) ---------
sub scan_subtrees_for_large {
    my ($subtree_roots, $threshold) = @_;
    my @hits;
    my @stack = map { [$_,0] } @$subtree_roots;
    while (my $fr = pop @stack) {
        my ($d,$lvl)=@$fr;
        next unless -e $d;
        next unless -d _;
        opendir(my $dh,$d) or next;
        while (defined(my $e=readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $p = "$d/$e";
            if (-d $p) { push @stack, [$p,$lvl+1]; next; }
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

# --------- Ключ файла для "новизны" ---------
sub file_key { my ($dev,$ino,$size,$mtime)=@_; return join(':',$dev,$ino,$size,$mtime); }

# --------- Сборка письма ---------
sub build_email_message {
    my (%a) = @_;
    my ($from,$to_csv,$subject,$body,$date) = @a{qw/from to_csv subject body_text date_header/};
    my $to = $to_csv // ''; $to =~ s/\s+//g; $to =~ s/,/, /g;
    my $hdr = "";
    $hdr .= "From: $from\n";
    $hdr .= "To: $to\n";
    $hdr .= "Subject: $subject\n";
    $hdr .= "Date: $date\n";
    $hdr .= "MIME-Version: 1.0\n";
    $hdr .= "Content-Type: text/plain; charset=UTF-8\n\n";
    return $hdr.$body;
}
sub preview_print {
    my ($text,$to_stderr)=@_;
    my $io = $to_stderr ? *STDERR : *STDOUT;
    print $io "================= EMAIL PREVIEW BEGIN =================\n";
    print $io $text;
    print $io "\n================= EMAIL PREVIEW  END  =================\n";
}

# ===================== ОСНОВНОЕ =====================
ensure_state_dir($STATE_DIR);

my $hostname = do { my $h=`hostname`; chomp $h; $h; };

# Загрузка состояний
my $files_seen  = load_file_state($STATE_FILE_KEYS);
my %files_seen  = %$files_seen;
my $dirs_state  = load_dir_state($STATE_DIR_INFO);   # path=>{mtime,hot,ttl}
my %dirs_state  = %$dirs_state;

# 0) Лёгкий проход: до уровней проектов и служебных
my $proj_list   = list_dirs_to_level(\@ROOT_DIRS, $PROJECT_LEVEL); # [path,level]
my %projects;
for my $it (@$proj_list) {
    my ($p,$lvl)=@$it;
    next unless $lvl==$PROJECT_LEVEL;
    $projects{$p}=1;
}
my $serv_list   = list_dirs_to_level([keys %projects], $SERVICE_LEVEL); # [path,level]
my %service_dirs;
for my $it (@$serv_list) {
    my ($p,$lvl)=@$it;
    next unless $lvl==$SERVICE_LEVEL;
    $service_dirs{$p}=1;
}

# 1) Решаем, какие "служебные" папки сканировать глубоко
my @candidates;
for my $sd (sort keys %service_dirs) {
    my @st = stat($sd); next unless @st;
    my $sd_mtime = $st[9] // 0;

    my $rec = $dirs_state{$sd} // { mtime=>0, hot=>0, ttl=>0 };
    my $hot = $rec->{hot} || 0;

    # если служебная папка новая/изменилась или "горячая" — в кандидаты
    if ($hot || $sd_mtime != ($rec->{mtime} // 0)) {
        push @candidates, $sd;
        $rec->{mtime} = $sd_mtime;
        $dirs_state{$sd} = $rec;
        next;
    }

    # если проект (родитель) менялся — тоже кандидат
    if ($sd =~ m{^(.+)/[^/]+$}) {
        my $parent = $1;
        my @pst = stat($parent);
        if (@pst) {
            my $pm = $pst[9] // 0;
            my $prec = $dirs_state{$parent} // { mtime=>0, hot=>0, ttl=>0 };
            if ($pm != ($prec->{mtime}//0)) {
                push @candidates, $sd;
            }
            # обновим запись родителя
            $prec->{mtime} = $pm;
            $dirs_state{$parent} = $prec;
        }
    }
}

# Плюс: всегда сканируем "горячие" папки, даже если их mtime не менялся
for my $path (keys %dirs_state) {
    my $r = $dirs_state{$path};
    next unless $r->{hot};
    next if grep { $_ eq $path } @candidates;
    # считаем "служебной", только если она действительно на нужном уровне
    if ($service_dirs{$path}) { push @candidates, $path; }
}

# Уникализируем кандидатов
my %uniq; @candidates = grep { !$uniq{$_}++ } @candidates;

# 2) Глубокий проход только по кандидатам
my $hits = scan_subtrees_for_large(\@candidates, $THRESHOLD_BYTES);

# 3) Только "новые" файлы (по ключу dev:ino:size:mtime)
my (@new_hits, @new_keys);
for my $h (@$hits) {
    my $k = file_key(@{$h}{qw/dev ino size mtime/});
    next if $files_seen{$k};
    push @new_hits, $h;
    push @new_keys, $k;
}

# 4) Помечаем папки, где нашли большие файлы, как "горячие"
my %serv_with_hits;
for my $h (@new_hits) {
    if ($h->{path} =~ m{^(.+)/[^/]+$}) {
        my $dir = $1;
        # поднимаем до ближайшей "служебной" папки
        my $svc = $dir;
        while ($svc =~ m{^(.+)/[^/]+$} && !$service_dirs{$svc}) { $svc = $1; }
        if ($service_dirs{$svc}) {
            $serv_with_hits{$svc} = 1;
        }
    }
}
for my $svc (keys %serv_with_hits) {
    my $r = $dirs_state{$svc} // { mtime=>0, hot=>0, ttl=>0 };
    $r->{hot} = 1;
    $r->{ttl} = 0;  # сброс TTL
    $dirs_state{$svc} = $r;
}

# 5) TTL для hot (если включен)
if ($HOT_TTL_RUNS > 0) {
    for my $svc (keys %service_dirs) {
        my $r = $dirs_state{$svc} // next;
        next unless $r->{hot};
        if (!$serv_with_hits{$svc}) {
            $r->{ttl}++;
            if ($r->{ttl} >= $HOT_TTL_RUNS) {
                $r->{hot} = 0; $r->{ttl}=0;
            }
            $dirs_state{$svc} = $r;
        }
    }
}

# 6) Если новых нет — тихо выходим
if (!@new_hits) {
    # обновим состояния каталогов (mtime/hot/ttl)
    ensure_state_dir($STATE_DIR);
    save_dir_state($STATE_DIR_INFO, \%dirs_state);
    print "No NEW files >= ".human_size($THRESHOLD_BYTES)." found. Candidates: ".scalar(@candidates)."\n";
    exit 0;
}

# 7) Письмо
my $utc_now = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));
my $body = "";
$body .= "Large files report (NEW ONLY, staged-scan)\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "Scanned   : $utc_now (UTC)\n";
$body .= "Host      : $hostname\n";
$body .= "Roots     : ".join(', ', @ROOT_DIRS)."\n";
$body .= "Scanned   : ".scalar(@candidates)." service folder(s)\n\n";

for my $h (@new_hits) {
    my $hr = human_size($h->{size});
    $body .= "File     : $h->{path}\n";
    $body .= "Size     : $hr ($h->{size} bytes)\n";
    $body .= "Modified : ".format_time($h->{mtime})."\n";
    $body .= "CTime    : ".format_time($h->{ctime})."\n";
    $body .= "Directory: ".($h->{path} =~ m{^(.+)/[^/]+$} ? $1 : '.')."\n";
    $body .= "----------------------------------------\n";
}

my $subject   = "$SUBJECT_PREFIX >= ".human_size($THRESHOLD_BYTES)." on $hostname (NEW)";
my $date_hdr  = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));
my $email_txt = build_email_message(
    from        => $FROM,
    to_csv      => $RECIPIENTS,
    subject     => $subject,
    body_text   => $body,
    date_header => $date_hdr,
);

# 8) Предпросмотр / отправка
if ($DEBUG_PREVIEW || $DRY_RUN) { preview_print($email_txt, $PREVIEW_TO_STDERR); }
if (!$DRY_RUN) {
    my $cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $cmd" or die "Cannot open sendmail: $!";
    print $sm $email_txt;
    close $sm or warn "sendmail exited with status $?";
}

# 9) Сохранить состояния
ensure_state_dir($STATE_DIR);
append_file_keys($STATE_FILE_KEYS, \@new_keys);
save_dir_state($STATE_DIR_INFO, \%dirs_state);

print "Email ".($DRY_RUN ? "previewed (dry-run, not sent)" : "sent")
    ." to: $RECIPIENTS. New files reported: ".scalar(@new_hits)
    ."; scanned service folders: ".scalar(@candidates)."\n";

exit 0;
