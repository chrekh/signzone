use strict;
use warnings;
use 5.010;

use Getopt::Long;
use Pod::Usage;

# Hardcoded path
$ENV{PATH} = '/usr/sbin:/usr/bin';

Getopt::Long::Configure('bundling', 'no_auto_abbrev');
my %opts = (c => '/etc/bind/signzone.conf');
GetOptions(\%opts, 'c=s', 'n', 's', 'f', 'r', 'printconf') || pod2usage;

{    # main (kind of)
    our %config;
    &readconfig;
    &printconf if (exists $opts{printconf});

    chdir $config{dbdir} || die "chdir $config{dbdir} failed: $!";

    my $now = time;    # To avoid calling time several times, silly, I know. ;)

    # Put keys in separate lists
    my %active  = (ksk => [], zsk => []);
    my %publish = (ksk => [], zsk => []);
    for my $key (&listkeys) {

        # Skip keys that are not zone-keys
        unless ($key->{zk}) {
            warn "$key->{name} is not a zone-key";
            next;
        }

        # Fix key if delete-date is before inactivation
        if ( $key->{Delete} < $key->{Inactive} ) {
            warn "$key->{name}: delete-time is before inactivation.\n";
            warn "fixing it...\n";
            my $deltime = $key->{Inactive} + $config{delete}{$key->{type}};
            my @cmd = ('dnssec-settime', '-D', &mktime($deltime), "$config{keydir}/$key->{name}");
            say "@cmd";
            unless ( exists $opts{n} ) {
                system @cmd;
                die unless $? == 0;
            }
            $key->{Delete} = $deltime;
        }

        # Skip keys that are deleted (from zone)
        if (exists $key->{Delete} && $now > $key->{Delete} ) {

            # And delete the keyfile if that time has arrived.
            if ( $now > $key->{Delete} + $config{remove}) {
                say "rm $key->{name}";
                unless (exists $opts{n}) {
                    unlink "$config{keydir}/$key->{name}.key";
                    unlink "$config{keydir}/$key->{name}.private";
                }
            }
            next;
        }

        # Keys that should be published
        if ($now >= $key->{Publish}) {

            # Active keys
            if ($now >= $key->{Activate} && $now < $key->{Inactive}) {
                push(@{ $active{ $key->{type} } }, $key);
            }

            # inactive keys
            else {
                push(@{ $publish{ $key->{type} } }, $key);
            }
        }
    }

    for my $type (qw<ksk zsk>) {

        # If we have no active keys, we must make one now.
        unless (@{ $active{$type} }) {
            push @{ $active{$type} },
                &makekey(
                    $type, $now, $now,
                    $now + $config{inactive}{$type},
                    $now + $config{inactive}{$type} + $config{delete}{$type}
                );
        }

        # Find the key with the latest inactivation-time
        my ($lastkey) =
            sort { $b->{Inactive} <=> $a->{Inactive} } (@{ $active{$type} }, @{ $publish{$type} });

        # Make a new published key if that $lastkeys inactivation-time
        # is less than prepublish-time away
        my $t = $lastkey->{Inactive};
        if ($t < $now + $config{prepublish}{$type}) {
            push @{ $publish{$type} },
                &makekey(
                    $type, $now, $t,
                    $t + $config{inactive}{$type},
                    $t + $config{inactive}{$type} + $config{delete}{$type}
                );
        }
    }

    # Compare present keydb with keylist, to be able to tell if we
    # should write a new keydb
    my $do_sign = 0;
    if (! exists $opts{f} && open(KEYFILE, '<', $config{keydb})) {
        my %keys;
        while (<KEYFILE>) {
            chomp;
            if (my ($keyname,$active) = /include.+(K$config{zone}\.+\S+)\.key\s*;\s*[kz]sk\s*(\*?)/) {
                if ( $active ) {
                    $keys{active}{$keyname} = 1;
                }
                else {
                    $keys{publish}{$keyname} = 1;
                }                    
                next;
            }
        }
        close KEYFILE;
        for my $type (qw<ksk zsk>) {
            for (@{ $active{$type} }) {
                unless (delete $keys{active}{ $_->{name} }) {
                    $do_sign = 1;
                    last;
                }
            }
            for (@{ $publish{$type} }) {
                unless (delete $keys{publish}{ $_->{name} }) {
                    $do_sign = 1;
                    last;
                }
            }
        }
        $do_sign = 1 unless (keys %{$keys{active}} == 0 && keys %{$keys{publish}} == 0);
    }
    else {
        $do_sign = 1;
    }

    # Write active and published keys to the keydb to be included in the zone.
    if (!exists $opts{n} && $do_sign) {
        open(KEYFILE, '>', $config{keydb}) || die "open $config{keydb} failed: $!";
    }

    # length for printf. Since all keys are for the same zone the
    # length is equal, so just use the length of the first active ksk.
    my $keynamelength = length($active{ksk}[0]->{name});
    printf("  %-${keynamelength}s  type        active          delete\n",'Key');;
    for my $type (qw<ksk zsk>) {
        for my $key (sort { $a->{Activate} <=> $b->{Activate} }
                         (@{ $active{$type} }, @{ $publish{$type} })) {
            my $is_active = $now >= $key->{Activate} && $now <= $key->{Inactive} ? '*' : '';
            printf(
                "%-2s%-${keynamelength}s  %s %s -> %s   %s\n",
                $is_active, $key->{name}, $key->{type},
                &date($key->{Activate}),
                &date($key->{Inactive}),
                &date($key->{Delete}),
            );
            if (!exists $opts{n} && $do_sign) {
                print KEYFILE '$include ', "$config{keydir}/$key->{name}.key ; $key->{type} $is_active\n"
            }
        }
    }
    close KEYFILE if (!exists $opts{n} && $do_sign);

    if (exists $opts{s} && ($do_sign || exists $opts{f} )) {
        say "increment serial";
        &increment_serial unless (exists $opts{n});
        my @cmd = ('dnssec-signzone', '-S', '-K', $config{keydir}, '-o', $config{zone});
        push @cmd, $config{zonefile};
        say "@cmd";
        unless (exists $opts{n}) {
            system @cmd;
            die unless $? == 0;
        }

        if (exists $opts{r}) {
            my @cmd = ('rndc', 'reload', $config{zone}, 'in');
            push(@cmd, $config{view}) if ($config{view} ne q<>);
            say "@cmd";
            unless (exists $opts{n}) {
                system @cmd;
                die unless $? == 0;
            }
        }
    }
}

sub listkeys {
    our %config;
    my @result;
    opendir(KEYDIR, $config{keydir}) || die "opendir $config{keydir} failed: $!";
    while (readdir(KEYDIR)) {
        next unless (-f "$config{keydir}/$_");
        if (my ($name) = /^(K$config{zone}\.\+\d+\+\d+)\.key/) {
            my $key = { name => $name };
            &keyinfo($key);
            push(@result, $key);
        }
    }
    closedir KEYDIR;
    return @result;
}

sub keyinfo {
    my $key = shift;
    our %config;

    # Get timing-info using dnssec-settime
    my @cmd = ('dnssec-settime', '-up', 'all', "$config{keydir}/$key->{name}");
    open(CMD, '-|', @cmd) || die;
    while (<CMD>) {
        chomp;
        if (my ($type, $val) = /^(\w+):\s+(\d+)$/) {
            $key->{$type} = $val;
            next;
        }
    }
    close CMD;
    die unless $? == 0;

    # Get more info by parsing the keyfile
    open(KEYFILE, '<', "$config{keydir}/$key->{name}.key")
        || die "open $key->{name}.key failed: $!";
    while (<KEYFILE>) {
        chomp;
        next if /^;/;    # skip comments
        if (my ($zone, $flags, $type, $algo) = /^(\S+)\s+IN\s+DNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s/) {
            $key->{zk}     = $flags & 0400;                  # Bit 7  RFC4034
            $key->{revoke} = $flags & 0200;                  # Bit 8  RFC5011
            $key->{type}   = $flags & 01 ? 'ksk' : 'zsk';    # Bit 15 RFC4034/RFC3757
        }
    }
    close KEYFILE;
}

sub makekey {
    my ($type, $p, $a, $i, $d) = @_;
    our %config;
    my @cmd = (
        'dnssec-keygen', '-r', $config{randomdev}, '-b', $config{keysize}{$type},
        '-K', $config{keydir}
    );
    push @cmd, '-f', 'KSK' if ($type eq 'ksk');
    push @cmd, '-n', 'ZONE', '-P', &mktime($p), '-A', &mktime($a),
        '-I', &mktime($i), '-D', &mktime($d), "$config{zone}.";
    say "@cmd";
    if (exists $opts{n}) {

        # return a fake key
        return {
            name     => "K$config{zone}.+005+99999",
            Created  => time,
            Publish  => $p,
            Activate => $a,
            Inactive => $i,
            Delete   => $d,
            zk       => 1,
            revoke   => '',
            type     => $type,
        };
    }
    my $key;
    open(CMD, '-|', @cmd) || die;
    $_ = <CMD>;
    say;
    close CMD;
    die unless $? == 0;
    chomp;

    if (my ($name) = /^(K$config{zone}\.\+\d+\+\d+)$/) {
        $key = { name => $name };
        &keyinfo($key);
    }
    else {
        die "no key found\n";
    }
    return $key;
}

sub mktime {
    my @result;
    for (@_) {
        my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = gmtime($_);

        push @result,    # YYYYMMDDHHMMSS
            sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
    }
    return @result;
}

sub date {
    my $t = shift;
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($t);
    return sprintf("%02d-%02d-%02d", $year % 100, $mon + 1, $mday);
}

sub readconfig {

    # Defaults ( and also valid configuration )
    our %config = (
        zone       => 'foo.org',
        dbdir      => '/var/named',
        randomdev  => '/dev/urandom',
        keysize    => { ksk => 2048,  zsk => 768 },
        inactive   => { ksk => '1y',  zsk => '5w' },
        delete     => { ksk => '2w',  zsk => '2w' },
        remove     => { ksk => '10w', zsk => '10w' },
        prepublish => { ksk => '6w',  zsk => '6w' },
        keydir     => 'keys',
        keydb      => undef,
        zonefile   => undef,
        view       => '',
        serialfmt  => 'keep',
    );

    if (open(CONFIG, '<', $opts{c})) {
        while (<CONFIG>) {
            chomp;
            next if (/^\s*$/);
            next if (/^#/);

            # single key
            if (my ($key, $val) = /^\s*(\S+)\s*=\s*(\S+)/) {
                die "Invalid config $key in $opts{c} line $.\n" unless (exists $config{$key});
                die "Missing type (ksk|zsk) in $opts{c} line $.\n"
                    if (ref($config{$key}) eq 'HASH');
                $config{$key} = $val;
                next;
            }

            # double key
            if (my ($key, $type, $val) = /^\s*(\S+)\s+(\S+)\s*=\s*(\S+)/) {
                die "Invalid config: $key $type in $opts{c} line $.\n"
                    unless (exists $config{$key}{$type});
                $config{$key}{$type} = $val;
                next;
            }
            die "parse error in $opts{c} line $.\n";
        }
        close CONFIG;
    }
    else {
        warn "open $opts{c} failed: $!";
        warn "*** using default configuration ***\n";
    }
    $config{keydb}    = "$config{zone}-dnskey.db" unless (defined $config{keydb});
    $config{zonefile} = "$config{zone}.db"        unless (defined $config{zonefile});

    # Prepend dbdir to relative paths
    for (qw<keydir keydb zonefile>) {
        $config{$_} = "$config{dbdir}/$config{$_}" unless (substr($config{$_}, 0, 1) eq '/');
    }

    # convert times to seconds
    my $day  = 60 * 60 * 24;
    my $week = 7 * $day;
    my $mon  = 30 * $day;
    my $year = 365 * $day;
    for my $type (qw<ksk zsk>) {
        for (qw<inactive delete prepublish>) {
            no warnings 'numeric';
            $config{$_}{$type} = $config{$_}{$type} * $day
                if (substr($config{$_}{$type}, -1, 1) eq 'd');
            $config{$_}{$type} = $config{$_}{$type} * $week
                if (substr($config{$_}{$type}, -1, 1) eq 'w');
            $config{$_}{$type} = $config{$_}{$type} * $mon
                if (substr($config{$_}{$type}, -1, 1) eq 'm');
            $config{$_}{$type} = $config{$_}{$type} * $year
                if (substr($config{$_}{$type}, -1, 1) eq 'y');
        }
    }
}

sub printconf {
    our %config;
    for my $key (sort keys %config) {
        if (ref($config{$key}) eq 'HASH') {
            for my $type (sort keys %{ $config{$key} }) {
                say "$key $type = $config{$key}{$type}";
            }
        }
        else {
            say "$key = $config{$key}";
        }
    }
    exit 0;
}

sub increment_serial {
    our %config;
    return if ($config{serialfmt} eq 'keep');

    open(ZONEFILE, '<', $config{zonefile}) || die "open $config{zonefile} failed: $!";
    my @zone = <ZONEFILE>;
    close ZONEFILE;

    my $changed = 0;
    for (@zone) {
        if ($config{serialfmt} eq 'increment'
                && s/^(\s*)(\d+)\s+;\s+serial$/sprintf("%s%-11d; serial",$1,$2+1)/e) {
            $changed = 1;
            last;
        }
        if ($config{serialfmt} eq 'unixtime'
                && s/^(\s*)(\d+)\s+;\s+serial$/sprintf("%s%-11d; serial",$1,time)/e) {
            $changed = 1;
            last;
        }
    }
    return unless $changed;

    open(ZONEFILE, '>', $config{zonefile}) || die "open $config{zonefile} failed: $!";

    print ZONEFILE @zone;

    close ZONEFILE;
}

=head1 NAME

B<signzone> - A dnssec key management tool

=head1 SYNOPSIS

B<signzone>
S<[ B<-c> I<configfile> ]>
S<[ B<-s> ]>
S<[ B<-r> ]>
S<[ B<-f> ]>
S<[ B<-n> ]>
S<[ B<--printconf> ]>

=head1 OPTIONS

=over

=item B<-c> I<configfile>

Use I<configfile> as configurationfile instead of default which is
F</etc/bind/signzone.conf>

=item B<-s>

Sign the zone (if needed), using dnssec-signzone

=item B<-r>

Reload the zone (if signed), using rndc

=item B<-f>

force signing if B<-s>, and reload if B<-r> even if nothing has changed.

=item B<-n>

noaction

=item B<--printconf>

Print the active configuration values.

=back

=head1 DESCRIPTION

B<signzone> is a wrapper tool around dnssec tools from bind, that
manages the keys used to sign a zone.  The keys active state, and
lifetime as specified to dnssec-keygen is respected, and new keys are
created when needed, using timing values specified in the
configuration file.

=head2 configfile syntax

Lines beginning with # is ignored, and can be used for comments.

The values for B<keydir>, B<keydb> and B<zonefile> is relative to
B<dbdir> unless specified as absolute.

All configuration variables have default values.

Time vaulues is specified as E<lt>integerE<gt>(d,w,m,y), where d is
for days, w is for weeks, m is for months, and y is for years. If no
letter is specified, the value is in seconds.

=over

=item B<zone> = I<zone>

Which dns zone to manage keys for.

=item B<dbdir> = I<dir>

Main zone database directory, Default is F</var/named>.

=item B<keydir> = I<dir>

Directoy to look for, and store, keyfiles in. Default is F<keys>.

=item B<keydb> = I<file>

File to write include-statements for the keys to use in. This file
should the be included from the zone-file. Default is F<B<E<lt>zoneE<gt>>-dnskey.db>.

=item B<zonefile> = I<file>

The (unsigned) zonefile for the zone. Default is F<B<E<lt>zoneE<gt>>.db>

=item B<keysize ksk> = I<nr>

The keysize to use when generating new ksk (key-signing-key). Default is 2048

=item B<keysize zsk> = I<nr>

The keysize to use when generating new zsk (zone-signing-key). Default is 768

=item B<inactive ksk> = I<time>

How long time, since activation, a ksk is active (used to sign the
zone). Default is 1y.

=item B<inactive zsk> = I<time>

How long time (since activation) a zsk is active (used to sign the
zone). Default is 5w.

=item B<delete ksk> = I<time>

How long time, after marked inactive, a zsk is to be deleted (from the
zone, the keyfile is not deleted). Default is 2w.

=item B<delete zsk> = I<time>

How long time, after marked inactive, a zsk is to be deleted (from the
zone, the keyfile is not deleted). Default is 2w.

=item B<remove ksk> = I<time>

How long after the ksk is deleted from the zone, until the keyfile is
removed from disk. Default is 10w

=item B<remove zsk> = I<time>

How long after the zsk is deleted from the zone, until the keyfile is
removed from disk. Default is 10w

=item B<prepublish ksk> = I<time>

How long time, before activation, a ksk is published, (and created if
not created by other tool). Default is 6w.

=item B<prepublish zsk> = I<time>

How long time, before activation, a zsk is published, (and created if
not created by other tool). Default is 6w.

=item B<randomdev> = I<file>

Which randomdev to use when creating keys. Default is F</dev/urandom>.

=item B<serialfmt> = I<keep|increment|unixtime>

Determine if and how serial should be updated in the zonefile if
option B<-s> is used. I<keep> = do nothing. I<increment> = increment
integer by one, and I<unixtime> = use current systemtime (seconds
since 1970-01-01 00:00:00 GMT)

=item B<view> = I<view>

The bind view the zone is in. Only needed for rndc if
using option B<-r>. Default is no view.

=back

=head1 SEE ALSO

L<dnssec-keygen(8)|dnssec-keygen>,
L<dnssec-signzone(8)|dnssec-signzone>

=cut
