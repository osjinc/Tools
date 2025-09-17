#!/usr/bin/env perl
# monitor_large_newonly.pl
use strict;
use warnings;
use Fcntl qw(:flock :DEFAULT);
use POSIX qw(strftime);
use File::Path qw(make_path);
use Encode qw(encode);

# ===================== CONFIG =====================
# Порог размера (в байтах). Пример: 2*1024*1024*1024 = 2 GiB
my $THRESHOLD_BYTES = 2 * 1024 * 1024 * 1024;

# Директории для сканирования (рекурсивно)
my @ROOT_DIRS = (
    '/var/data',
    # '/mnt/storage',
);

# Кому отправлять (несколько адресов — через запятую)
my $RECIPIENTS = 'ops@example.com,admin@example.com';

# От кого
my $FROM = 'monitor@localhost';

# Префикс темы письма
my $SUBJECT_PREFIX = 'ALERT: large files found';

# Путь к статус-файлу (запоминает уже разосланные файлы)
my $STATE_FILE = '/var/lib/monitor_large/state.db';

# Максимальная глубина (0 = без ограничения)
my $MAX_DEPTH = 0;

# Исключать симлинки (1 = да)
my $SKIP_SYMLINKS = 1;

# --- Отладка / предпросмотр ---
# Печатать текст письма (заголовки+тело) перед отправкой
my $DEBUG_PREVIEW = 1;
# Не отправлять письмо (только показать предпросмотр)
my $DRY_RUN = 0;
# Куда печатать предпросмотр: 1 = STDERR, 0 = STDOUT
my $PREVIEW_TO_STDERR = 1;

# Путь к sendmail
my $SENDMAIL_BIN = '/usr/sbin/sendmail';

# =================== END CONFIG ===================

# --------- Утилиты ---------
sub human_size {
    my ($bytes) = @_;
    my @units = ('B','K','M','G','T','P');
    my $i = 0;
    my $v = $bytes + 0;
    while ($v >= 1024 && $i < $#units) {
        $v /= 1024;
        $i++;
    }
    return $i == 0 ? sprintf("%d %s", $bytes, $units[$i])
                   : sprintf("%.2f %s", $v, $units[$i]);
}

sub load_state {
    my ($path) = @_;
    my %seen;
    if (-f $path) {
        open my $fh, '<', $path or die "Failed to open state file $path: $!";
        while (my $line = <$fh>) {
            chomp $line;
            $seen{$line} = 1 if $line ne '';
        }
        close $fh;
    } else {
        # ensure dir exists
        my ($dir) = ($path =~ m{^(.+)/[^/]+$});
        if ($dir && !-d $dir) {
            make_path($dir) or die "Failed to create state dir $dir: $!";
        }
    }
    return \%seen;
}

sub save_state_append {
    my ($path, $keys) = @_;
    return unless @$keys;
    open my $fh, '>>', $path or die "Failed to open state file $path for append: $!";
    flock($fh, LOCK_EX) or die "Failed to lock state file $path: $!";
    for my $k (@$keys) {
        print {$fh} "$k\n";
    }
    close $fh;
}

sub format_time {
    my ($epoch) = @_;
    return defined $epoch ? strftime("%Y-%m-%d %H:%M:%S %Z", localtime($epoch)) : 'unknown';
}

sub file_key {
    # Уникальный ключ файла: dev:ino:size:mtime
    my ($dev, $ino, $size, $mtime) = @_;
    return join(':', $dev, $ino, $size, $mtime);
}

# --------- Сканер (итеративный, быстрый) ---------
sub scan_dirs {
    my ($roots, $threshold, $max_depth, $skip_symlinks) = @_;
    my @hits;
    my @stack = map { [$_, 0] } @$roots;

    while (my $frame = pop @stack) {
        my ($dir, $depth) = @$frame;
        next unless -e $dir;
        next if $skip_symlinks && -l $dir;
        next unless -d _;

        opendir(my $dh, $dir) or next;
        while (defined(my $e = readdir($dh))) {
            next if $e eq '.' || $e eq '..';
            my $path = "$dir/$e";

            if ($skip_symlinks && -l $path) { next; }

            if (-d $path) {
                if (!$max_depth || $depth < $max_depth) {
                    push @stack, [$path, $depth + 1];
                }
                next;
            }

            next unless -f _;
            my @st = stat($path);
            next unless @st;

            my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
                $atime,$mtime,$ctime,$blksize,$blocks) = @st;

            next unless defined $size && $size > $threshold;

            push @hits, {
                path  => $path,
                dev   => $dev,
                ino   => $ino,
                size  => $size,
                mtime => $mtime,
                ctime => $ctime, # это не "creation", но иногда полезно
            };
        }
        closedir($dh);
    }
    return \@hits;
}

# --------- Сборка письма ---------
sub build_email_message {
    my (%args) = @_;
    my $from         = $args{from};
    my $to_csv       = $args{to_csv};
    my $subject      = $args{subject};
    my $body_text    = $args{body_text};
    my $date_header  = $args{date_header};

    my $hdr  = '';
    $hdr .= "From: $from\n";
    my $to_header = $to_csv // '';
    $to_header =~ s/\s+//g;
    $to_header =~ s/,/, /g;
    $hdr .= "To: $to_header\n";
    $hdr .= "Subject: $subject\n";
    $hdr .= "Date: $date_header\n";
    $hdr .= "MIME-Version: 1.0\n";
    $hdr .= "Content-Type: text/plain; charset=UTF-8\n";
    $hdr .= "\n";

    return $hdr . $body_text;
}

sub preview_print {
    my ($text, $to_stderr) = @_;
    my $io = $to_stderr ? *STDERR : *STDOUT;
    print $io "================= EMAIL PREVIEW BEGIN =================\n";
    print $io $text;
    print $io "\n================= EMAIL PREVIEW  END  =================\n";
}

# --------- Основная логика ---------
my $hn = `hostname`;
chomp $hn;
my $hostname = $hn;

my $state = load_state($STATE_FILE);
my %already = %$state;

my $hits = scan_dirs(\@ROOT_DIRS, $THRESHOLD_BYTES, $MAX_DEPTH, $SKIP_SYMLINKS);

# Отфильтровать только новые (не встречавшиеся ранее) по ключу dev:ino:size:mtime
my @new_hits;
my @new_keys;
for my $h (@$hits) {
    my $k = file_key(@{$h}{qw/dev ino size mtime/});
    next if exists $already{$k};
    push @new_hits, $h;
    push @new_keys, $k;
}

if (!@new_hits) {
    print "No NEW files >= ".human_size($THRESHOLD_BYTES)." found. Nothing to send.\n";
    exit 0;
}

# Сформировать тело письма
my $utc_now = strftime("%Y-%m-%d %H:%M:%SZ", gmtime(time));
my $body = '';
$body .= "Large files report (NEW ONLY)\n";
$body .= "Threshold : ".human_size($THRESHOLD_BYTES)." ($THRESHOLD_BYTES bytes)\n";
$body .= "Scanned   : $utc_now (UTC)\n";
$body .= "Host      : $hostname\n";
$body .= "Roots     : ".join(', ', @ROOT_DIRS)."\n";
$body .= "\n";

for my $h (@new_hits) {
    my $hr = human_size($h->{size});
    my $mtime_s = format_time($h->{mtime});
    my $ctime_s = format_time($h->{ctime});
    $body .= "File     : $h->{path}\n";
    $body .= "Size     : $hr ($h->{size} bytes)\n";
    $body .= "Modified : $mtime_s\n";
    $body .= "CTime    : $ctime_s\n";
    $body .= "Directory: ".($h->{path} =~ m{^(.+)/[^/]+$} ? $1 : '.')."\n";
    $body .= "----------------------------------------\n";
}

my $subject   = "$SUBJECT_PREFIX >= ".human_size($THRESHOLD_BYTES)." on $hostname (NEW)";
my $date_hdr  = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time));

# Собираем полный текст письма (заголовки + тело)
my $email_text = build_email_message(
    from        => $FROM,
    to_csv      => $RECIPIENTS,
    subject     => $subject,
    body_text   => $body,
    date_header => $date_hdr,
);

# Предпросмотр (debug)
if ($DEBUG_PREVIEW || $DRY_RUN) {
    preview_print($email_text, $PREVIEW_TO_STDERR);
}

# Отправка (если не dry-run)
if (!$DRY_RUN) {
    my $sendmail_cmd = "$SENDMAIL_BIN -t -oi";
    open my $sm, "| $sendmail_cmd" or die "Cannot open sendmail: $!";
    # Гарантируем отправку в UTF-8 (если пути содержат не-ASCII)
    print $sm encode('UTF-8', $email_text);
    close $sm or warn "sendmail exited with status $?";
}

# Апдейтим состояние — добавляем только что разосланные ключи
save_state_append($STATE_FILE, \@new_keys);

print "Email " . ($DRY_RUN ? "previewed (dry-run, not sent)" : "sent") . " to: $RECIPIENTS. New files reported: ".scalar(@new_hits)."\n";
exit 0;
