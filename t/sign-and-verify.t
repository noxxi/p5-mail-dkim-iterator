use strict;
use warnings;
use Test::More;
use Mail::DKIM::Iterator;

plan tests => 13;

for my $c (qw(
    simple/simple
    simple/relaxed
    relaxed/relaxed
    relaxed/simple
    relaxed
    simple
)) {
    for my $algo (qw(rsa-sha1 rsa-sha256)) {
	#diag("c=$c a=$algo");
	my $ok = eval {
	    my $m = sign([ mail() ], c => $c, a => $algo );
	    verify([$m],dns());
	};
	my $err = $@ || ($ok ? '':'unknown error');
	is( $err,'', "c=$c a=$algo");
    }
}

# expect verification fail because of wrong pubkey
my $ok = eval {
    my $m = sign([mail()], s => 'bad');
    verify([$m],dns());
};
my $err = $@ || ($ok ? '':'unknown error');
is( $err,"bad status status=perm-fail error=header sig mismatch\n",
    "wrong pubkey");

# create signature
sub sign {
    my ($mail,%args) = @_;
    my $dkim = Mail::DKIM::Iterator->new( sign => {
	d => 'example.com',
	s => 'good',
	h => 'from:to:subject',
	':key' => priv_key_pem(),
	%args,
    });

    # sign the mail
    my $rv;
    for(@$mail,'') {
	$rv = $dkim->append($_) and last;
    }
    $rv || die "no result after end of mail\n";
    @$rv == 1 or die "expected a single result, got ".int(@$rv)."\n";
    $rv->[0]->status == DKIM_SUCCESS 
	or die "unexpected status ".( $rv->[0]->status // '<undef>' )."\n";
    my $dkim_sig = $rv->[0]->signature;
    return $dkim_sig . join("",@$mail);
}

# validate signature
sub verify {
    my ($mail,$dns) = @_;

    my $dkim = Mail::DKIM::Iterator->new;
    my $rv;
    for(@$mail,'') {
	$rv = $dkim->append($_) and last;
    }
    $rv || die "no result after end of mail\n";
    @$rv == 1 or die "expected a single result, got ".int(@$rv)."\n";
    defined $rv->[0]->status and die "expected status undef\n";

    # feed DNS record into dkim object
    $rv = $dkim->result($dns);
    @$rv == 1 or die "expected a single result, got ".int(@$rv)."\n";
    $rv->[0]->status == DKIM_SUCCESS or die 
	"bad status status=" . ($rv->[0]->status//'<undef>')
	. " error=" . ($rv->[0]->error//'') . "\n";
    1;
}



sub priv_key_pem { <<'KEY'; }
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

sub dns {{ 
    'good._domainkey.example.com' => <<'DKIM_KEY',
v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOD/2mm2FfRCkBhtQkE3Wl2M3A9E8PJiSkvciLrSoTePnHC0MSLaNXYUmFHT//zT4ZebruQDgPVsLRLVmWssVaKn9EpKQcd55qVKApFNZSoev5sdzXP9g+AuZYtnkSHzlilqiSttHkadXSAyJ8WOlMC0kTPWEkL+FyWDyezKuj9QIDAQAB
DKIM_KEY
    'bad._domainkey.example.com' => <<'DKIM_KEY',
v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
DKIM_KEY
}}

sub mail { <<'MAIL'; }
From: me
To: you
Subject: whatever
Message-Id: <foo@bar.com>
In-Reply-To:
References:

Hi Foo,
Going to the Bar   Barfoot,

Greetings,
Bar


MAIL

