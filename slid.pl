#!/usr/bin/perl

# slid.pl - simple linux intrusion detector

use strict;
use warnings;

our $signatures_file  = 'signatures';       # database to compare to
our $found_signatures = 'md5sigs_current';  # found signatures from find command
our $diff_file        = 'signatures.diff';  # diff file to send

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
    close $cmd_pipe;
    close $out_fh;
}

sub compare_files { 
    # remove previous diff file
    if ( -e $diff_file ) {
        unlink( $diff_file );
    }

    if ( -e $signatures_file ) {
        my $cmd = "diff $signatures_file $found_signatures"; 
        open my $cmd_pipe, "-|", $cmd or die "pipe from $cmd failed: $!";
        open my $out_fh, ">", $diff_file or die "write to $diff_file failed: $!"; 
        while ( <$cmd_pipe> ) {
            print { $out_fh } $_;
        }
        close $cmd_pipe;
        close $out_fh;
    } else {
        mv $found_signatures $signatures_file;
        print "no prior report found.\n"; 
    }
}

sub send_report {

    use MIME::Lite;
    my $msg = MIME::Lite->new(
        From     => 'root@om.houqe.lab',
        To       => 'scott.gillespie@netiq.com',
        Cc       => 'scott_layne_gillespie@hotmail.com',
        Subject  => 'home dir checksum diffs',
        Type     => 'TEXT',
        Encoding => 'base64',
        Path     => $diff_file
    );

    $msg->send();
    print "email sent."; 
}

sub gather_and_report {
    get_md5sums(); 
    compare_files();
    send_report();
}
gather_and_report(); 
