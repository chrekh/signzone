#! /usr/bin/perl

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

my $min = 60;
my $hour = 60 * $min;
my $day = 60 * $hour;
my $week = 7 * $day;

{    # main (kind of)
    our $zone = 'chrekh.se';
    my $dbdir = '/var/bind';
    our $keydir = "$dbdir/zsk";
    my %t = ( active => 5*$week, inactive => 6*$week, delete => 15*$week );
    my @keys = &listkeys;
    my @active;
    my @publish;
    my @include;

    for my $key (@keys) {
        if ( exists $key->{Delete} && time > $key->{Delete} ) {
            say "rm $key->{name}";
            #unlink("$keydir/$key->{name}.key");
            #unlink("$keydir/$key->{name}.private");
            next;
        }
        if ( time > $key->{Activate} && time < $key->{Inactive} ) {
            push @active, $key;
            next;
        }
        if ( time > $key->{Publish} && time < $key->{Inactive} ) {
            push @publish, $key;
            next;
        }
        push @include, $key;
    }

    unless (@active) {

        # Make a new key that is active immediately
        push @active,
            &makekey(
                time, time,
                time + $t{inactive},
                time + $t{delete},
            );
    }

    @active = sort { $a->{Inactive} <=> $b->{Inactive} } @active;

    unless (@publish) {

        # Make a new key that is active when last key is inactivated  p a i d
        push @publish,
            &makekey(
                time,
                $active[-1]->{Inactive},
                $active[-1]->{Inactive} + $t{inactive},
                $active[-1]->{Inactive} + $t{delete},
            );
    }

    # Write active and published keys to a file to be included in the zone.
    my $keyfile = "$keydir/keylist";
    open( KEYFILE, '>', $keyfile ) || die "open $keyfile failed: $!";
    for my $key ( @active, @publish, @include ) {
        print KEYFILE '$include ', "$keydir/$key->{name}.key", "\n";
    }
    close(KEYFILE);
    1;
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
            &gettimes($key);
            push( @result, $key );
        }
    }
    closedir(DIR);
    return @result;
}

sub gettimes {
    my $key = shift;
    our $keydir;
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
}

sub makekey {
    my ( $p, $a, $i, $d ) = mktime(@_);
    our $zone;
    our $keydir;
    my @cmd = (
        'dnssec-keygen', '-r', '/dev/urandom', '-b', '768', '-K', $keydir, '-n', 'ZONE', '-P', $p,
        '-A', $a, '-I', $i, '-D', $d, "$zone."
    );
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
        &gettimes($key);
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
