use strict;
use warnings;
use 5.010;

# C = Created
# P = Publish
# A = Activate
# R = Revoke
# I = Inactive
# D = Delete

# key1 PA------RI-----D
# key2 P-------A-----RI-----D
# key3         P------A-----RI-----D

my $min  = 60;
my $hour = 60 * $min;
my $day  = 60 * $hour;
my $week = 7 * $day;

{    # main (kind of)

    our $zone = 'chrekh.se';
    my $dbdir = '/tmp/named';
    our $keydir = "$dbdir/keys";
    my $keyfile = "$dbdir/dnskey.db";
    my %t = ( active => 5 * $week,
              inactive => 6 * $week,
              delete => 15 * $week,
              prepublish => 2 * $week,
          );

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
        if ( $now > $key->{Delete} ) {
            say "rm $key->{name}";
            # unlink "$keydir/$key->{name}.key";
            # unlink "$keydir/$key->{name}.private";
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
                &makekey($type,$now,$now,$now+$t{inactive},$now+$t{delete}); # p a i d
        }

        # Sort active keys by inactivation date
        @{$active{$type}} = sort { $a->{Inactive} <=> $b->{Inactive} } @{$active{$type}};

        # If there are no prepublished keys, and only one active key,
        # and its inactivation time is less than $prepublish away we
        # ned to make a new published key, that is to become active
        # the same time the active key gets inactive.
        unless ( @{$publish{$type}} ) {
            my $t = $active{$type}->[0]->{Inactive};
            if ( @{$active{$type}} == 1 && $t < $now + $t{prepublish} ) {
                push @{$publish{$type}},
                    &makekey($type,$now,$t,$t+$t{inactive},$t+$t{delete}); # p a i d
            }
        }
    }

    # Write active and published keys to the keyfile to be included in the zone.
    open( KEYFILE, '>', $keyfile ) || die "open $keyfile failed: $!";
    for my $type ( qw<ksk zsk> ) {
        for my $key ( @{$active{$type}}, @{$publish{$type}} ) {
            print KEYFILE '$include ', "$keydir/$key->{name}.key ; $key->{type}\n";
        }
    }
    close KEYFILE;
}

sub listkeys {
    our $keydir;
    our $zone;

    my @result;
    opendir( DIR, $keydir ) || die "opendir $keydir failed: $!";
    while ( readdir(DIR) ) {
        next unless ( -f "$keydir/$_" );
        if ( my ($name) = /^(K$zone\.\+\d+\+\d+)\.key/ ) {
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
    our $keydir;

    # Get timing-info using dnssec-settime
    my @cmd = ( 'dnssec-settime', '-up', 'all', "$keydir/$key->{name}" );
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

    # Get more info by parsing the keyfile
    open( FILE, '<', "$keydir/$key->{name}.key" ) || die "open $key->{name}.key failed: $!";
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
    our $zone;
    our $keydir;
    my @cmd = ('dnssec-keygen', '-r', '/dev/urandom', '-b', '768', '-K', $keydir );
    push @cmd,'-f', 'KSK' if ($type eq 'ksk');
    push @cmd,
        '-n', 'ZONE', '-P', $p,
        '-A', $a, '-I', $i, '-D', $d, "$zone.";
    say "@cmd";
    my $key;
    open( CMD, '-|', @cmd ) || die "run @cmd failed: $!";
    $_ = <CMD>;
    say;
    close(CMD);
    die unless $? == 0;
    chomp;

    if ( my ($name) = /^(K$zone\.\+\d+\+\d+)$/ ) {
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
