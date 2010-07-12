package OAuth::Lite2::Client::UsernameAndPassword;

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
use OAuth::Lite2::Formatters;
use OAuth::Lite2::Client::TokenResponseParser;

sub new {
    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        id                => 1,
        secret            => 1,
        # format          => { optional => 1 },
        access_token_uri  => { optional => 1 },
        refresh_token_uri => { optional => 1 },
        agent             => { optional => 1 },
    });

    my $self = bless {
        id                => undef,
        secret            => undef,
        access_token_uri  => undef,
        refresh_token_uri => undef,
        %args,
    }, $class;

    unless ($self->{agent}) {
        $self->{agent} = LWP::UserAgent->new;
        $self->{agent}->agent(
            join "/", __PACKAGE__, $OAuth::Lite2::VERSION);
    }

    # $self->{format} ||= 'json';
    $self->{response_parser} = OAuth::Lite2::Client::TokenResponseParser->new;

    return $self;
}

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        username     => 1,
        password     => 1,
        scope        => { optional => 1 },
        uri          => { optional => 1 },
        # secret_type => { optional => 1 },
        # format      => { optional => 1 },
    });

    unless (exists $args{uri}) {
        $args{uri} = $self->{access_token_uri}
            || Carp::croak "uri not found";
    }

    # $args{format} ||= $self->{format};

    my %params = (
        grant_type    => 'basic-credentials',
        client_id     => $self->{id},
        client_secret => $self->{secret},
        username      => $args{username},
        password      => $args{password},
        # format      => $args{format},
    );

    $params{scope} = $args{scope}
        if $args{scope};

    # $params{secret_type} = $args{secret_type}
    #     if $args{secret_type};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{uri}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my ($token, $errmsg);
    try {
        $token = $self->{response_parser}->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $token || $self->error($errmsg);

}

sub refresh_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        refresh_token => 1,
        uri           => { optional => 1 },
        # secret_type => { optional => 1 },
        # format      => { optional => 1 },
    });

    unless (exists $args{uri}) {
        $args{uri} = $self->{access_token_uri}
            || Carp::croak "uri not found";
    }

    # $args{format} ||= $self->{format};

    my %params = (
        grant_type    => 'refresh-token',
        client_id     => $self->{id},
        client_secret => $self->{secret},
        refresh_token => $args{refresh_token},
        # format        => $args{format},
    );

    # $params{secret_type} = $args{secret_type}
    #     if $args{secret_type};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{uri}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my ($token, $errmsg);
    try {
        $token = $self->{response_parser}->parse($res);
    } catch {
        $errmsg = "$_";
    };
    return $token || $self->error($errmsg);
}

1;
