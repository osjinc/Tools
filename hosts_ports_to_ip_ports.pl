#!/usr/bin/env perl
use strict;
use warnings;

my $in  = shift(@ARGV) // "hosts_ports.csv";
my $out = shift(@ARGV) // "ip_ports.csv";

open my $fh, "<", $in  or die "Cannot read $in: $!";
open my $oh, ">", $out or die "Cannot write $out: $!";

my $header = <$fh>;
die "Input CSV must start with 'host,port'\n"
  unless defined $header && $header =~ /^\s*host\s*,\s*port\s*$/i;

print $oh "ip,port\n";

my %seen; # ip|port

sub is_ipv4 {
  my ($v) = @_;
  return 0 unless $v =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  return 0 if grep { $_ > 255 } ($1,$2,$3,$4);
  return 1;
}

sub getent_lines {
  my (@cmd) = @_;
  my @lines;
  if (open my $ph, "-|", @cmd) {
    @lines = <$ph>;
    close $ph;
  }
  return @lines;
}

sub resolve_v4 {
  my ($host) = @_;
  my @ips;

  # NSS-aware resolution (DNS, /etc/hosts, sssd, ldap, etc.)
  my @out = getent_lines("getent", "ahostsv4", $host);
  for my $line (@out) {
    if ($line =~ /^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+/) {
      push @ips, $1;
    }
  }

  # fallback
  if (!@ips) {
    @out = getent_lines("getent", "hosts", $host);
    for my $line (@out) {
      if ($line =~ /^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+/) {
        push @ips, $1;
      }
    }
  }

  my %u; $u{$_} = 1 for @ips;
  return sort keys %u;
}

while (my $line = <$fh>) {
  chomp $line;
  $line =~ s/\r$//;
  next if $line =~ /^\s*$/;

  my ($host, $port) = split(/\s*,\s*/, $line, 2);
  next unless defined $host && defined $port;

  $host =~ s/^\s+|\s+$//g;
  $port =~ s/^\s+|\s+$//g;
  next if $host eq '' || $port eq '';

  # 1) Если host уже IPv4 — сразу пишем
  if (is_ipv4($host)) {
    my $k = "$host|$port";
    next if $seen{$k}++;
    print $oh "$host,$port\n";
    next;
  }

  # 2) Иначе пробуем резолвить
  my @ips = resolve_v4($host);
  next unless @ips;   # не резолвится — пропускаем

  for my $ip (@ips) {
    my $k = "$ip|$port";
    next if $seen{$k}++;
    print $oh "$ip,$port\n";
  }
}

close $fh;
close $oh;

print "Wrote $out (", scalar(keys %seen), " unique ip:port)\n";
