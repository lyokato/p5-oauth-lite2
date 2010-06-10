package OAuth::Lite2::Client::Device;

use strict;
use warnings;

use base 'Class::ErrorHandler';

use Params::Validate qw(HASHREF);
use Carp ();
use Try::Tiny;
use URI;
use LWP::UserAgent;
use HTTP::Request;

use OAuth::Lite2;
use OAuth::Lite2::Util qw(build_content);
use OAuth::Lite2::Error;
use OAuth::Lite2::Formatters;
use OAuth::Lite2::Client::TokenResponseParser;
use OAuth::Lite2::Client::CodeResponseParser;

sub new {
    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        id                => 1,
#       secret            => 1,
        format            => { optional => 1 },
        access_token_url  => { optional => 1 },
        refresh_token_url => { optional => 1 },
        agent             => { optional => 1 },
    });

    my $self = bless {
        id                => undef,
#       secret            => undef,
        access_token_url  => undef,
        refresh_token_url => undef,
        %args,
    }, $class;

    unless ($self->{agent}) {
        $self->{agent} = LWP::UserAgent->new;
        $self->{agent}->agent(
            join "/", __PACKAGE__, $OAuth::Lite2::VERSION);
    }

    $self->{format} ||= 'json';
    $self->{token_response_parser} = OAuth::Lite2::Client::TokenResponseParser->new;
    $self->{code_response_parser} = OAuth::Lite2::Client::CodeResponseParser->new;

    return $self;
}

sub get_code {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        scope  => { optional => 1 },
        format => { optional => 1 },
        url    => { optional => 1 },
    });

    unless (exists $args{url}) {
        $args{url} = $self->{access_token_url}
            || Carp::croak "url not found";
    }

    $args{format} ||= $self->{format};

    my %params = (
        type      => 'device_code',
        client_id => $self->{id},
        format    => $args{format},
    );

    $params{scope} = $args{scope} if $args{scope};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{url}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my ($code, $errmsg);
    try {
        $code = $self->{code_response_parser}->parse($res);
    } catch {
        $errmsg = $_->isa("OAuth::Lite2::Error")
            ? $_->message
            : $_;
    };
    return $code || $self->error($errmsg);
}

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        code        => 1,
        secret_type => { optional => 1 },
        format      => { optional => 1 },
        url         => { optional => 1 },
    });

    unless (exists $args{url}) {
        $args{url} = $self->{access_token_url}
            || Carp::croak "url not found";
    }

    $args{format} ||= $self->{format};

    my %params = (
        type      => 'device_token',
        client_id => $self->{id},
        code      => $args{code},
        format    => $args{format},
    );

    $params{secret_type} = $args{secret_type}
        if $args{secret_type};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{url}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my ($token, $errmsg);
    try {
        $token = $self->{token_response_parser}->parse($res);
    } catch {
        $errmsg = $_->isa("OAuth::Lite2::Error")
            ? $_->message
            : $_;
    };
    return $token || $self->error($errmsg);
}

1;
