use strict;
use warnings;
use lib 'lib';
use Mail::DKIM::Iterator;

# run against t/corpus/ from Mail::DKIM

my %globdns;

file:
for my $file (@ARGV) {
    my $dkim = Mail::DKIM::Iterator->new(\%globdns);
    my $mail = do { 
	open( my $fh,'<',$file) or do {
	    warn "$file: open $!\n";
	    next;
	};
	local $/; <$fh> 
    };

    my $subj = $mail =~m{^Subject:[ \t]*(.*\n(?:[ \t].*\n)*)}mi 
	? $1:'NO SUBJECT';
    $subj =~s{[\r\n]+}{}g;
    print STDERR "\n--- $subj | $file\n";

    my $rv;
    while (!$rv) {
	my $buf = substr($mail,0,20,'');
	if ($buf ne '') {
	    # will return true once we have enough data
	    $rv = $dkim->append($buf);
	} else {
	    $rv = $dkim->append('') or do {
		print STDERR " W DKIM->append still undef at eof\n";
		next file;
	    };
	}
    }


    check_rv:
    # check if we need more DNS records
    my $retry = 0;
    my %dns;
    for(@$rv) {
	my ($dnsname,$status,$error) = @$_;
	defined $status and next;
	$retry++;
	my $txt = fakedns($dnsname);
	if (!$txt || $txt =~m{^\~}) {
	    $dns{$dnsname} = undef;
	} elsif ($txt eq 'NXDOMAIN') {
	    $dns{$dnsname} = [];
	} else {
	    $dns{$dnsname} = [ $txt ];
	}
    }
    if ($retry) {
	$rv = $dkim->verify(\%dns);
	goto check_rv;
    }

    for(@$rv) {
	my ($name,$status,$error) = @$_;
	if (!defined $status) {
	    print STDERR " U $name\n";
	} elsif ($status == DKIM_PERMFAIL) {
	    print STDERR " F $name $error\n";
	} elsif ($status == DKIM_SOFTFAIL) {
	    print STDERR " f $name $error\n";
	} elsif ($status == DKIM_TEMPFAIL) {
	    print STDERR " T $name $error\n";
	} elsif ($status == DKIM_SUCCESS) {
	    print STDERR " V $name\n";
	} else {
	    die $status
	}
    }
    print STDERR " W $_\n" for @{ $dkim->warning || [] };


}

my %fakedns;
sub fakedns {
    if (!%fakedns) {
	my $fake = <<'FAKEDNS';
# this file contains DNS records used by verifier.t
#
selector1._domainkey.messiah.edu  k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhMlYqwtUA9UrrDcNp/IMtdFnytggDl5oIAzJ55oWzPILZE7eX4hLdP6WperHm1WJ9M32XsiKrr4TDbWfp4WjGWBnXf8QMi+WlDuEFOvwVRC/uWy+sAiEf3VcBR5KjGvDovPnGSnW8uDntSOY4HlkTJF/BTWnk29zKmlGyGnw9mQIDAQAB
test1._domainkey.messiah.edu  v=DKIM1; t=y; s=email; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
test2._domainkey.messiah.edu  v=DKIM1; s=email:web:fine; x1 = extra ; t = y:n:extra; h=md5:sha1; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ== ; 
test3._domainkey.messiah.edu  v=DKIM1; g=jl*g; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
test4._domainkey.messiah.edu  v=DKIM1; g=; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
test5._domainkey.messiah.edu  v=DKIM1; t=s; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad1._domainkey.messiah.edu  v=DKIM3; t=y; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad2._domainkey.messiah.edu  k=rsa; t; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad3._domainkey.messiah.edu  k=foobar; t=y; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad4._domainkey.messiah.edu  v=DKIM1; s=chat; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad7._domainkey.messiah.edu  v=DKIM1; h=bad; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testbad8._domainkey.messiah.edu  v=DKIM1; g=*poe; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==
testrevoked._domainkey.messiah.edu  k=rsa; t=y; p=
s1024._domainkey.yahoo.com  k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfmJiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;
beta._domainkey.gmail.com  t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC69TURXN3oNfz+G/m3g5rt4P6nsKmVgU1D6cw2X6BnxKJNlQKm10f8tMx6P6bN7juTR1BeD8ubaGqtzm2rWK4LiMJqhoQcwQziGbK1zp/MkdXZEWMCflLY6oUITrivK7JNOLXtZbdxJG2y/RAHGswKKyVhSP9niRsZF/IBr5p8uQIDAQAB
jakla2._domainkey.ijs.si  v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvWSehCSmnxlhzM+P1Ai+7CgzeAcvkL3RdoHFq8JwtpKN3iLnp/s1yRwE/heAi4QQXxDRdlB0bJm5NxZOsckzK7tJM8EdkebMjyXeKOzBKoJaOIlsx4WC2qHqORB0RLqm4lqJFYZJpUypEpskeAGy7WBG7a+1hOlir9+Tf9xtOkwIDAQAB
shan._domainkey.vmt2.cis.att.net  v=DKIM1; k=rsa; h=sha1:sha256:sha512;n=send%20comments%20to%20tony%40att%2Ecom; g=*; s=*;p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhALSQ1y/+tHT1d9XvpiVap4Z+GFaydEmDgfC48m3wLLmDqfKBADWYIqrCnfKPvZPzGYzo+aJMEiAOTtiNxPWYToiTfJlTpn2YyEEz6OUIXw0uc+NfEQviN4QQr0jVX9yRjwIDAQAB
foo._domainkey.vmt2.cis.att.net  v=DKIM1; k=rsa; n=send%20comments%20to%20tony%40att%2Ecom; g=*; s=*;p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhALSQ1y/+tHT1d9XvpiVap4Z+GFaydEmDgfC48m3wLLmDqfKBADWYIqrCnfKPvZPzGYzo+aJMEiAOTtiNxPWYToiTfJlTpn2YyEEz6OUIXw0uc+NfEQviN4QQr0jVX9yRjwIDAQAB
nonexistent._domainkey.messiah.edu NXDOMAIN
test3._domainkey.blackhole.messiah.edu ~~Query timed out~~
test3._domainkey.blackhole2.messiah.edu ~~SERVFAIL~~
FAKEDNS
	for(split(m{\n},$fake)) {
	    s{\s*(?:#.*)?$}{};
	    $_ eq '' and next;
	    my ($name,$answer) = split(' ',$_,2);
	    $fakedns{$name} = $answer;
	}
    }
    return @_ ? $fakedns{$_[0]} : \%fakedns;
}
