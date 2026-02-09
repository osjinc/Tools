#!/usr/bin/env perl
use strict;
use warnings;
use File::Find;

my $root = "/data/project_conf";
my $out  = shift(@ARGV) // "hosts_ports.csv";

my %seen;  # key = "host:port" => 1

sub add_pair {
  my ($h, $p) = @_;
  return unless defined $h && defined $p;

  $h =~ s/^\s+|\s+$//g;
  $p =~ s/^\s+|\s+$//g;

  $h =~ s/^["']|["']$//g;
  $p =~ s/^["']|["']$//g;

  return if $h eq '' || $p eq '';
  return unless $p =~ /^\d+$/;

  $seen{"$h:$p"} = 1;
}

sub parse_any_value_for_pairs {
  my ($v) = @_;
  return unless defined $v;

  # 1) SQL Server instance form: host\INSTANCE,1433  or host\INST:1433
  while ($v =~ /([A-Za-z0-9._-]+)(?:\\[^,;:]+)?\s*[,;:]\s*(\d{2,5})/g) {
    add_pair($1, $2);
  }

  # Чтобы не поймать хвост "INSTANCE,1433" как отдельный host,
  # удаляем "\INSTANCE" из копии перед общими паттернами
  my $v2 = $v;
  $v2 =~ s/\\[^,;:]+//g;

  # 2) host:port / host,port / host;port
  while ($v2 =~ /([A-Za-z0-9._-]+)\s*[:;,]\s*(\d{2,5})/g) {
    add_pair($1, $2);
  }

  # 3) Oracle-ish: (HOST=...)(PORT=...)
  while ($v2 =~ /\(\s*host\s*=\s*([^)]+?)\s*\)\s*\(\s*port\s*=\s*(\d{2,5})\s*\)/ig) {
    add_pair($1, $2);
  }

  # 4) Иногда адреса списком: host1,1521,host2,1521
  while ($v2 =~ /([A-Za-z0-9._-]+)\s*[,;]\s*(\d{2,5})/g) {
    add_pair($1, $2);
  }
}

sub parse_ini {
  my ($path) = @_;
  open my $fh, "<", $path or return;

  my @host_keys = qw(
    host hostname server servername address networkaddress
    ipaddress dbhost
  );

  my @port_keys = qw(
    port portnumber serverport servicenameport
    tcpport listenerport
  );

  my %kv; # per-section cache

  while (my $line = <$fh>) {
    chomp $line;
    $line =~ s/\r$//;

    next if $line =~ /^\s*(?:[;#].*)?$/;

    if ($line =~ /^\s*\[(.+?)\]\s*$/) {
      %kv = ();
      next;
    }

    next unless $line =~ /^\s*([^=]+?)\s*=\s*(.*?)\s*$/;
    my ($k, $v) = (lc($1), $2);

    $k =~ s/\s+//g;
    $v =~ s/^\s+|\s+$//g;

    $kv{$k} = $v;

    # эвристики по значению (host:port / host,port / (HOST=)(PORT=) и т.п.)
    parse_any_value_for_pairs($v);

    # связка host-key + port-key (когда раздельно)
    my ($host, $port);

    for my $hk (@host_keys) {
      if (exists $kv{$hk}) { $host = $kv{$hk}; last; }
    }
    for my $pk (@port_keys) {
      if (exists $kv{$pk}) { $port = $kv{$pk}; last; }
    }

    if (defined $host && defined $port) {
      my @hosts = split(/\s*[,;]\s*/, $host);
      for my $h (@hosts) {
        next unless $h =~ /[A-Za-z0-9._-]/;
        add_pair($h, $port);
      }
    }
  }

  close $fh;
}

sub parse_tnsnames {
  my ($path) = @_;
  open my $fh, "<", $path or return;
  local $/ = undef;
  my $txt = <$fh>;
  close $fh;

  while ($txt =~ /\(\s*host\s*=\s*([^)]+?)\s*\)\s*\(\s*port\s*=\s*(\d{2,5})\s*\)/ig) {
    my ($h, $p) = ($1, $2);
    $h =~ s/^\s+|\s+$//g;
    add_pair($h, $p);
  }

  while ($txt =~ /host\s*=\s*([A-Za-z0-9._-]+).*?port\s*=\s*(\d{2,5})/igs) {
    add_pair($1, $2);
  }
}

find(
  {
    wanted => sub {
      my $p = $File::Find::name;
      return unless -f $p;

      # ВСЕ ini-файлы в дереве project_conf/*
      if ($p =~ /\.ini$/i) {
        parse_ini($p);
        return;
      }

      # tnsnames.ora (если рядом/внутри)
      if ($p =~ /\/tnsnames\.ora$/i) {
        parse_tnsnames($p);
        return;
      }
    },
    no_chdir => 1
  },
  glob("$root/*")
);

open my $outfh, ">", $out or die "Cannot write $out: $!";
print $outfh "host,port\n";
for my $k (sort keys %seen) {
  my ($h, $p) = split(/:/, $k, 2);
  print $outfh "$h,$p\n";
}
close $outfh;

print "Wrote $out (", scalar(keys %seen), " unique host:port)\n";
