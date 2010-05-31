package OAuth::Lite2::Signer;

use strict;
use warnings;

use MIME::Base64 qw(encode_base64);
use String::Random;
use URI;
use Params::Validate;

use OAuth::Lite2::Error;
use OAuth::Lite2::Signer::Algorithms;

sub sign {
    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        secret          => 1,
        algorithm       => 1,
        method          => 1,
        url             => 1,
        debug_nonce     => { optional => 1 },
        debug_timestamp => { optional => 1 },
    });

    my $uri = URI->new($args{url});
    OAuth::Lite2::Error::InvalidURIScheme->throw
        unless ($uri->scheme eq 'http' || $uri->scheme eq 'https');

    my $params = {
        nonce     => $args{debug_nonce}     || $class->_gen_nonce(),
        timestamp => $args{debug_timestamp} || $class->_gen_timestamp(),
        algorithm => $args{algorithm},
    };

    my $string = $class->normalize_string(%$params,
        method => $args{method},
        host   => $uri->host,
        port   => $uri->port || 80,
        url    => $args{url},
    );

    my $algorithm =
        OAuth::Lite2::Signer::Algorithms->get_algorithm(lc $args{algorithm})
            or OAuth::Lite2::Error::UnsupportedAlgorithm->throw($args{algorithm});

    my $signature = encode_base64($algorithm->hash($args{secret}, $string));
    chomp $signature;
    $params->{signature} = $signature;
    return $params;
}

sub normalize_string {
    my ($class, %args) = @_;
    $args{port} ||= 80;
    return join(",",
        $args{timestamp},
        $args{nonce},
        $args{algorithm},
        uc($args{method}),
        sprintf(q{%s:%d}, $args{host}, $args{port}),
        $args{url},
    );
}

sub _gen_nonce {
    my ($class, $digit) = @_;
    $digit ||= 10;
    my $random = String::Random->new;
    return $random->randregex( sprintf '[a-zA-Z0-9]{%d}', $digit );
}

sub _gen_timestamp {
    my $class = shift;
    return time();
}

sub verify {
    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        secret          => 1,
        algorithm       => 1,
        method          => 1,
        url             => 1,
        nonce           => 1,
        timestamp       => 1,
        signature       => 1,
    });

    my $uri = URI->new($args{url});

    my $params = {
        nonce     => $args{nonce},
        timestamp => $args{timestamp},
        algorithm => $args{algorithm},
    };

    my $string = $class->normalize_string(%$params,
        method => $args{method},
        host   => $uri->host,
        port   => $uri->port || 80,
        url    => $args{url},
    );

    my $algorithm =
        OAuth::Lite2::Signer::Algorithms->get_algorithm($args{algorithm})
            or OAuth::Lite2::Error::UnsupportedAlgorithm->throw($args{algorithm});

    my $signature = encode_base64($algorithm->hash($args{secret}, $string));
    chomp $signature;

    return ($args{signature} eq $signature);
}

1;
