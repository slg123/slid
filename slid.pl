#!/usr/bin/perl

# slid.pl - simple linux intrusion detector

use strict;
use warnings;

our $signatures_file  = 'signatures';            # database to compare to
our $found_signatures = 'md5sigs_current';  # found signatures from find command
our $diff_file        = 'signatures.diff';

if ( ! -e $signatures_file ) {
    print "no signatures file found. exiting.\n"; 
    exit 42;
}

# generate new md5sums for comparison with $signatures_file
sub get_md5sums {

    my $cmd = 'find /Unix2/Unix/scottg \( -wholename "/Unix2/Unix/scottg/perforce/projects/SLID/*" -o -wholename "/Unix2/Unix/scottg/perforce/*" \) -prune -o -print | xargs md5sum 2>/dev/null'; 

    if ( -e $found_signatures ) {
        unlink( $found_signatures ); 
    }
    open my $cmd_pipe, "-|", $cmd or die "pipe from $cmd failed: $!"; 
    open my $out_fh, ">", $found_signatures or die "write to $found_signatures failed: $!"; 
    while ( <$cmd_pipe> ) {
        print { $out_fh } $_; 
    }
}

#compare against current database
sub compare { 
    if ( -e $signatures_file ) {
        my $cmd = "diff $signatures_file $found_signatures"; 
        open my $cmd_pipe, "-|", $cmd or die "pipe from $cmd failed: $!";
        open my $out_fh, ">", $diff_file or die "write to $diff_file failed: $!"; 
        while ( <$cmd_pipe> ) {
            print { $out_fh } $_;
        }
    } else {
        mv $found_signatures $signatures_file;
        print "no prior report found.\n"; 
    }
}

sub send_report {
    use MIME::Lite;
    $msg = MIME::Lite->new(
        To      => 'scott.gillespie@netiq.com',
        From    => 'root@om.houqe.lab',
        Subject => "simple linux intrusion detector"
    );

    $msg->attach(
        Type     => "text/plain",
        Filename =>  $diff_file
    );
}

sub gather_and_report {
    get_md5sums(); 
    compare();
    send_report();
}
gather_and_report(); 
