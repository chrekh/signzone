use strict;
use warnings;
use 5.010;

use Getopt::Long;
use Pod::Usage;

{    # main (kind of)

    Getopt::Long::Configure( 'bundling', 'no_auto_abbrev' );
    our %opts = ( c => '/etc/bind/signzone.conf' );
    GetOptions(\%opts,'c=s') || pod2usage;

    our %config;
    &readconfig;

    my $now = time; # To avoid calling time several times, silly, I know. ;)

    # Put keys in separate lists
    my %active = ( ksk => [], zsk => [] );
    my %publish = ( ksk => [], zsk => [] );
    for my $key ( &listkeys ) {
        unless ( $key->{zk} ) {
            # Skip keys that are not zone-keys
            warn "$key->{name} is not a zone-key";
            next;
        }

        # Delete keys that should be deleted
        if ( exists $key->{Delete} && $now > $key->{Delete} ) {
            say "rm $key->{name}";
            #unlink "$config{keydir}/$key->{name}.key";
            #unlink "$config{keydir}/$key->{name}.private";
            next;
        }
        # Keys that should be published
        if ( $now > $key->{Publish} ) {
            # Active keys
            if ( $now > $key->{Activate} && $now < $key->{Inactive} ) {
                push(@{$active{$key->{type}}},$key);
            }
            # inactive keys
            else {
                push(@{$publish{$key->{type}}},$key);
            }
        }
    }

    for my $type ( qw<ksk zsk> ) {
        # If we have no active keys, we must make one now.
        unless ( @{$active{$type}} ) {
            push @{$active{$type}},
                &makekey($type,$now,$now,$now+$config{inactive},$now+$config{delete}); # p a i d
        }

        # If there are no prepublished keys, and only one active key,
        # and its inactivation time is less than $prepublish away we
        # ned to make a new published key, that is to become active
        # the same time the active key gets inactive.
        unless ( @{$publish{$type}} ) {
            my $t = $active{$type}->[0]->{Inactive};
            if ( @{$active{$type}} == 1 && $t < $now + $config{prepublish} ) {
                push @{$publish{$type}},
                    &makekey($type,$now,$t,$t+$config{inactive},
                             $t+$config{inactive}+$config{delete}); # p a i d
            }
        }
    }

    # Write active and published keys to the keydb to be included in the zone.
    open( KEYFILE, '>', $config{keydb} ) || die "open $config{keydb} failed: $!";
    for my $type ( qw<ksk zsk> ) {
        for my $key ( @{$active{$type}}, @{$publish{$type}} ) {
            say "use $key->{name} : $key->{type}";
            print KEYFILE '$include ', "$config{keydir}/$key->{name}.key ; $key->{type}\n";
        }
    }
    close KEYFILE;
}

sub listkeys {
    our %config;
    my @result;
    opendir( DIR, $config{keydir} ) || die "opendir $config{keydir} failed: $!";
    while ( readdir(DIR) ) {
        next unless ( -f "$config{keydir}/$_" );
        if ( my ($name) = /^(K$config{zone}\.\+\d+\+\d+)\.key/ ) {
            my $key = { name => $name };
            &keyinfo($key);
            push(@result,$key);
        }
    }
    closedir(DIR);
    return @result;
}

sub keyinfo {
    my $key = shift;
    our %config;

    # Get timing-info using dnssec-settime
    my @cmd = ( 'dnssec-settime', '-up', 'all', "$config{keydir}/$key->{name}" );
    open( CMD, '-|', @cmd ) || die "run @cmd failed: $!";
    while (<CMD>) {
        chomp;
        if ( my ( $type, $val ) = /^(\w+):\s+(\d+)$/ ) {
            $key->{$type} = $val;
            next;
        }
    }
    close CMD;
    die unless $? == 0;

    # Get more info by parsing the keydb
    open( FILE, '<', "$config{keydir}/$key->{name}.key" ) || die "open $key->{name}.key failed: $!";
    while (<FILE>) {
        chomp;
        next if /^;/;    # skip comments
        if ( my ( $zone,$flags,$type,$algo ) = /^(\S+)\s+IN\s+DNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s/ ) {
            $key->{zk}     = ( $flags & 0400 ) == 0400;    # Bit 7  RFC4034
            $key->{revoke} = ( $flags & 0200 ) == 0200;    # Bit 8  RFC5011
            $key->{type}   = ( $flags & 01 ) == 01 ? 'ksk' : 'zsk';        # Bit 15 RFC4034/RFC3757
        }
    }
    close FILE;
}

sub makekey {
    my $type = shift;
    my ( $p, $a, $i, $d ) = mktime(@_);
    our %config;
    my @cmd = ('dnssec-keygen', '-r', $config{randomdev}, '-b', $config{keysize}{$type}, '-K', $config{keydir} );
    push @cmd,'-f', 'KSK' if ($type eq 'ksk');
    push @cmd, '-n', 'ZONE', '-P', $p, '-A', $a, '-I', $i, '-D', $d, "$config{zone}.";
    say "@cmd";
    my $key;
    open( CMD, '-|', @cmd ) || die "run @cmd failed: $!";
    $_ = <CMD>;
    say;
    close(CMD);
    die unless $? == 0;
    chomp;

    if ( my ($name) = /^(K$config{zone}\.\+\d+\+\d+)$/ ) {
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
        my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = gmtime($_);

        # YYYYMMDDHHMMSS
        push @result,
            sprintf( "%04d%02d%02d%02d%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec );
    }
    return @result;
}

sub readconfig {
    our %opts;
    open(FILE,'<',$opts{c}) || die "open $opts{c} failed: $!";

    # Defaults ( and also valid configuration )
    our %config = (
        zone => 'foo.org',
        zonefile => 'foo.org.db',
        dbdir => '/var/named',
        randomdev => '/dev/urandom',
        keysize => { ksk => 2048, zsk => 768 },
        inactive => '6w',
        delete => '15w',
        prepublish => '2w',
        keydir => 'keys',
        keydb => 'dnskey.db',
    );

    while (<FILE>) {
        chomp;
        next if ( /^\s*$/ );
        next if ( /^#/ );

        # single key
        if ( my($key,$val) = /^\s*(\S+)\s*=\s*(\S+)/ ) {
            die "Invalid config $key in $opts{d} line $.\n" unless ( exists $config{$key} );
            $config{$key} = $val;
            next;
        }
        # double key (currently only keysize)
        if ( my($key,$type,$val) = /^\s*(\S+)\s+(\S+)\s*=\s*(\S+)/ ) {
            die "Invalid config: $key $type in $opts{d} line $.\n" unless ( exists $config{$key}{$type} );
            $config{$key}{$type} = $val;
            next;
        }
        die "parse error in $opts{c} line $.\n";
    }
    close FILE;

    # Prepend dbdir to relativa paths
    for ( qw<keydir keydb> ) {
        $config{$_} = "$config{dbdir}/$config{$_}" unless ( substr($config{$_},0,1) eq '/' );
    }

    # convert times to seconds
    my $min  = 60;
    my $hour = 60 * $min;
    my $day  = 24 * $hour;
    my $week = 7 * $day;
    my $mon  = 30 * $day;
    my $year = 365 * $day;
    for (qw<inactive delete prepublish> ) {
        no warnings 'numeric';
        $config{$_} = $config{$_} * $day  if ( substr($config{$_},-1,1) eq 'd' );
        $config{$_} = $config{$_} * $week if ( substr($config{$_},-1,1) eq 'w' );
        $config{$_} = $config{$_} * $mon  if ( substr($config{$_},-1,1) eq 'm' );
        $config{$_} = $config{$_} * $year if ( substr($config{$_},-1,1) eq 'y' );
    }
}
