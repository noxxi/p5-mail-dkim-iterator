use strict;
use warnings;

use lib 'lib';
use Mail::DKIM::Iterator;
use Getopt::Long qw(:config posix_default bundling);

sub usage {
    print STDERR <<USAGE;

This will read a mail from file or stdin and return the mail with the
appropriate DKIM-Signature header added. When reading from stdin the result will
be written to stdout, when reading from file the result will be written to a new
file with an appropriate suffix.
Default builtins for key, domain, selector and header are provided.

Usage: $0 [options] mail*
Options:
   -h|--help        this help
   -K|--key file    file with RSA key used to sign mail
   -D|--domain d    domain for d=..  ('example.local')
   -S|--selector s  selector for s=..  ('s')
   -H|--header h    header list for h=..
   -L|--length i    optional max body length to sign
   -C|--canon  c    canonicalization - default simple/simple
   --ext ext        extension to use for output files ('.dkim-signed')

USAGE
    exit(2);
}

my $key = _builtin_priv_key_pem();
my $domain = 'example.local';
my $selector = 's';
my $ext = '.dkim-signed';
my $canon = 'simple/simple';
my $header;
my $sign_length;
GetOptions(
    'h|help' => sub {usage()},
    'K|key=s' => sub {
	open(my $fh,'<',$_[1]) or die "cannot open $_[1]: $!";
	local $/;
	$key = <$fh>;
    },
    'D|domain=s' => \$domain,
    'S|selector=s' => \$selector,
    'H|header=s' => \$header,
    'L|length=i' => \$sign_length,
    'C|canon=s'  => \$canon,
    'ext=s' => \$ext,
);

my %args = (
    ':key' => $key,
    s => $selector,
    d => $domain,
    h => $header,
    c => $canon,
);

if (!@ARGV) {
    print sign( do { local $/; <STDIN> }, %args);
} else {
    for my $file (@ARGV) {
	open(my $in,'<',$file) or die "cannot open $file: $!";
	open(my $out,'>',$file.$ext) or die "cannot open $file$ext: $!";
	print $out sign( do { local $/; <$in> }, %args);
    }
}

# create signature
sub sign {
    my ($total_mail,%args) = @_;

    if (defined $sign_length) {
	if ($sign_length<0) {
	    $args{l} = $total_mail =~m{(\r?\n)\1(.*)\z}s && length($2);
	} else {
	    $args{l} = $sign_length;
	}
    }
    my $dkim = Mail::DKIM::Iterator->new( sign => \%args);

    my $rv;
    my @todo = \'';
    my $mail = [ $total_mail,'' ];
    while (@todo) {
	my $todo = shift(@todo);
	if (ref($todo)) {
	    die "no more data after end of mail" if !@$mail;
	    ($rv,@todo) = $dkim->next(shift(@$mail));
	} else {
	    die "there should no no DNS lookups needed for signing\n";
	}
    }
    @todo && die "still things to do at end of mail\n";
    $rv || die "no result after end of mail\n";

    @$rv == 1 or die "expected a single result, got ".int(@$rv)."\n";
    $rv->[0]->status == DKIM_SUCCESS
	or die "unexpected status ".( $rv->[0]->status // '<undef>' )."\n";
    my $dkim_sig = $rv->[0]->signature;
    return $dkim_sig . $total_mail;
}




sub _builtin_priv_key_pem { <<'KEY'; }
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDOD/2mm2FfRCkBhtQkE3Wl2M3A9E8PJiSkvciLrSoTePnHC0MS
LaNXYUmFHT//zT4ZebruQDgPVsLRLVmWssVaKn9EpKQcd55qVKApFNZSoev5sdzX
P9g+AuZYtnkSHzlilqiSttHkadXSAyJ8WOlMC0kTPWEkL+FyWDyezKuj9QIDAQAB
AoGAdU+JOhZvYsrtBV962mbxrU82I8lyUM+IQPmCeHJG5/sRSA3TS0AMI6zRLCUw
0DJKTjqM/yI0SBc+pdNJk4+G5f4g6fSXIJ4ZgBOcODtfvJd/lV6wFnPkvXkwqlTg
/hdy9b0dgxNuZoroGFRmPfoyRGKJ5Ki+YljD1LsIptGwLQECQQDzjQZe9vDp+/gW
bFRdK7yLtWbStS3JQaxYbgPWKOSX8rPQecR2eRKSQlLCn6Ivwg+Dsb1ZUm6rj6x1
zraf7G7hAkEA2JhprlVSYWsu3qzzMt7UVsOqjjUdw75eoYyaftSjUouv1I5JvKb4
uUWOdBrtJnK8UzyM8U58RVuTFxoWtOl7lQJBAMkIj0mz7Ag3xAA+SyTdBTUM92LV
yoVlgC0+IkyUVJxX6bUbzd888Odpd4bO3cEuHkBGZlVkhZV3cpOLnZNERgECQEmY
+IgJa/W4UvPNNtI5T1OwJvstZ1DFFii0uyaPoHODDZsfQkT9Q5TI4s/m+mBPKljq
QUYZkjaLGF8IOWD92UUCQQDcOgnxIpRuaIfxOEy4YVIErZC4aYqFKffn2KCHIok2
mLCwzP6+EOAZvHS1y2LkY/XSRSuZCRLDb5K3Jw8fIaEF
-----END RSA PRIVATE KEY-----
KEY
