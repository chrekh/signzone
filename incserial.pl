#! /usr/bin/perl

use 5.014;
use strict;
use warnings;

use Getopt::Long;
use Pod::Usage;

# Options with defaults
my %opts = ( serialfmt => 'increment' );

GetOptions(\%opts,'serialfmt=s','v') || pod2usage;

# main (kind of)
{
    my $zonefile = shift;
    unless ( defined $zonefile ) {
	say "zonefile not specified";
	pod2usage;
    }
    &increment_serial($zonefile);
}


sub increment_serial {
    my $zonefile = shift;
    return if ($opts{serialfmt} eq 'keep');
    say "increment serial";

    open(ZONEFILE, '<', $zonefile) || die "open $zonefile failed: $!";
    my @zone = <ZONEFILE>;
    close ZONEFILE;

    my $changed = 0;
    for (@zone) {
        if ($opts{serialfmt} eq 'increment'
                && s/^(\s*)(\d+)\s+;\s+serial$/sprintf("%s%-11d; serial",$1,$2+1)/e) {
            $changed = 1;
            last;
        }
        if ($opts{serialfmt} eq 'unixtime'
                && s/^(\s*)(\d+)\s+;\s+serial$/sprintf("%s%-11d; serial",$1,time)/e) {
            $changed = 1;
            last;
        }
	if ($opts{serialfmt} eq 'datestr'
	    && s/^(\s*)(\d{8})(\d{2})\s+;\s+serial$/sprintf("%s%-11d; serial",$1,&dateserial($2,$3))/e) {
            $changed = 1;
            last;
        }
    }
    return unless $changed;

    open(ZONEFILE, '>', $zonefile) || die "open $zonefile failed: $!";

    print ZONEFILE @zone;

    close ZONEFILE;
}

sub dateserial {
    my ($prevdate,$seq) = @_;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    my $curdate = sprintf("%04d%02d%02d",$year + 1900,$mon+1,$mday);
    return $prevdate . sprintf("%02d",$seq+1) if ($prevdate eq $curdate);
    return $curdate . "01";
}

=head1 NAME

B<incserial> - Increment serial in a zonefile

=head1 SYNOPSIS

B<incserial>
S<[ B<--serialfmt> I<keep|increment|unixtime|datestr> ]>
S<zonefile>

=head1 OPTIONS

=over

=item B<--serialfmt> I<keep|increment|unixtime|datestr>

Type of serial to generate. Default is increment.

=back

=head1 DESCRIPTION

B<incserial> increments serial in a DNS zonefile.

=cut
