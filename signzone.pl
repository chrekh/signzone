use strict;
use warnings;
use 5.010;

use Getopt::Long;
use Pod::Usage;

Getopt::Long::Configure( 'bundling', 'no_auto_abbrev' );
our %opts = ( c => '/etc/bind/signzone.conf' );
GetOptions( \%opts, 'c=s','s','n','r' ) || pod2usage;

{    # main (kind of)


    our %config;
    &readconfig;

    my $now = time;    # To avoid calling time several times, silly, I know. ;)

    # Put keys in separate lists
    my %active  = ( ksk => [], zsk => [] );
    my %publish = ( ksk => [], zsk => [] );
    for my $key (&listkeys) {
        unless ( $key->{zk} ) {

            # Skip keys that are not zone-keys
            warn "$key->{name} is not a zone-key";
            next;
        }

        # Delete keys that should be deleted
        if ( exists $key->{Delete} && $now > $key->{Delete} ) {
            say "rm $key->{name}";
            unless ( exists $opts{n} ) {
                unlink "$config{keydir}/$key->{name}.key";
                unlink "$config{keydir}/$key->{name}.private";
            }
            next;
        }

        # Keys that should be published
        if ( $now >= $key->{Publish} ) {

            # Active keys
            if ( $now >= $key->{Activate} && $now < $key->{Inactive} ) {
                push( @{ $active{ $key->{type} } }, $key );
            }

            # inactive keys
            else {
                push( @{ $publish{ $key->{type} } }, $key );
            }
        }
    }

    for my $type (qw<ksk zsk>) {

        # If we have no active keys, we must make one now.
        unless ( @{ $active{$type} } ) {
            push @{ $active{$type} },
                &makekey( $type, $now, $now,
                          $now + $config{inactive}{$type},
                          $now + $config{delete}{$type} );
        }

        # Find the key with the latest inactivation-time
        my ($lastkey)
            = sort { $b->{Inactive} <=> $a->{Inactive} }
            ( @{ $active{$type} }, @{ $publish{$type} } );

        # Make a new published key if that $lastkeys inactivation-time
        # is less than prepublish-time away
        my $t = $lastkey->{Inactive};
        if ( $t < $now + $config{prepublish}{$type} ) {
            push @{ $publish{$type} },
                &makekey(
                $type, $now, $t,
                $t + $config{inactive}{$type},
                $t + $config{inactive}{$type} + $config{delete}{$type}
                );
        }
    }

    # Write active and published keys to the keydb to be included in the zone.
    unless ( exists $opts{n} ) {
        open( KEYFILE, '>', $config{keydb} ) || die "open $config{keydb} failed: $!";
    }
    say "  Key                           type publish  activate inactivate";
    for my $type (qw<ksk zsk>) {
        for my $key ( sort { $a->{Activate} <=> $b->{Activate} }
            ( @{ $active{$type} }, @{ $publish{$type} } ) ) {
            my $is_active = $now >= $key->{Activate} && $now <= $key->{Inactive} ? '* ' : '  ';
            printf("%s%-30s %s %s %s %s\n",
                   $is_active,$key->{name},$key->{type},
                   &date( $key->{Publish} ),
                   &date( $key->{Activate} ),
                   &date( $key->{Inactive} ),
               );
            unless ( exists $opts{n} ) {
                print KEYFILE '$include ', "$config{keydir}/$key->{name}.key ; $key->{type}\n";
            }
        }
    }
    close KEYFILE unless ( exists $opts{n} );
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
            push( @result, $key );
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
        if ( my ( $zone, $flags, $type, $algo ) = /^(\S+)\s+IN\s+DNSKEY\s+(\d+)\s+(\d+)\s+(\d+)\s/ )
        {
            $key->{zk}     = ( $flags & 0400 ) == 0400;                # Bit 7  RFC4034
            $key->{revoke} = ( $flags & 0200 ) == 0200;                # Bit 8  RFC5011
            $key->{type}   = ( $flags & 01 ) == 01 ? 'ksk' : 'zsk';    # Bit 15 RFC4034/RFC3757
        }
    }
    close FILE;
}

sub makekey {
    my ( $type, $p, $a, $i, $d ) = @_;
    our %config;
    my @cmd = (
        'dnssec-keygen', '-r', $config{randomdev}, '-b', $config{keysize}{$type},
        '-K', $config{keydir}
    );
    push @cmd, '-f', 'KSK' if ( $type eq 'ksk' );
    push @cmd, '-n', 'ZONE', '-P', &mktime($p), '-A', &mktime($a),
               '-I', &mktime($i), '-D', &mktime($d), "$config{zone}.";
    say "@cmd";
    if ( exists $opts{n} ) {
        # return a fake key
        return {
            name     => "K$config{zone}+005+99999",
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

sub date {
    my $t = shift;
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime($t);
    return sprintf( "%02d-%02d-%02d", $year % 100, $mon + 1, $mday );
}

sub readconfig {
    our %opts;
    # Defaults ( and also valid configuration )
    our %config = (
        zone       => 'foo.org',
        zonefile   => 'foo.org.db',
        dbdir      => '/var/named',
        randomdev  => '/dev/urandom',
        keysize    => { ksk => 2048,  zsk => 768 },
        inactive   => { ksk => '1y',  zsk => '5w' },
        delete     => { ksk => '10w', zsk => '10w' },
        prepublish => { ksk => '3w', zsk => '5w' },
        keydir     => 'keys',
        keydb      => 'dnskey.db',
    );
    
    unless ( open( FILE, '<', $opts{c} ) ) {
        warn "open $opts{c} failed: $!";
        goto NOFILE;
    }
    while (<FILE>) {
        chomp;
        next if (/^\s*$/);
        next if (/^#/);

        # single key
        if ( my ( $key, $val ) = /^\s*(\S+)\s*=\s*(\S+)/ ) {
            die "Invalid config $key in $opts{c} line $.\n" unless ( exists $config{$key} );
            die "Missing type (ksk|zsk) in $opts{c} line $.\n" if ( ref($config{$key}) eq 'HASH' );
            $config{$key} = $val;
            next;
        }

        # double key
        if ( my ( $key, $type, $val ) = /^\s*(\S+)\s+(\S+)\s*=\s*(\S+)/ ) {
            die "Invalid config: $key $type in $opts{c} line $.\n"
                unless ( exists $config{$key}{$type} );
            $config{$key}{$type} = $val;
            next;
        }
        die "parse error in $opts{c} line $.\n";
    }
    close FILE;

  NOFILE:
    # Prepend dbdir to relativa paths
    for (qw<keydir keydb>) {
        $config{$_} = "$config{dbdir}/$config{$_}" unless ( substr( $config{$_}, 0, 1 ) eq '/' );
    }

    # convert times to seconds
    my $min  = 60;
    my $hour = 60 * $min;
    my $day  = 24 * $hour;
    my $week = 7 * $day;
    my $mon  = 30 * $day;
    my $year = 365 * $day;
    for my $type ( qw<ksk zsk> ) {
        for (qw<inactive delete prepublish>) {
            no warnings 'numeric';
            $config{$_}{$type} = $config{$_}{$type} * $day  if ( substr( $config{$_}{$type}, -1, 1 ) eq 'd' );
            $config{$_}{$type} = $config{$_}{$type} * $week if ( substr( $config{$_}{$type}, -1, 1 ) eq 'w' );
            $config{$_}{$type} = $config{$_}{$type} * $mon  if ( substr( $config{$_}{$type}, -1, 1 ) eq 'm' );
            $config{$_}{$type} = $config{$_}{$type} * $year if ( substr( $config{$_}{$type}, -1, 1 ) eq 'y' );
        }
    }
}
