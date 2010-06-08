package OAuth::Lite2::Client::WebServer;

use strict;
use warnings;

use Params::Validate qw(HASHREF);
use Carp ();
use bytes ();
use URI;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Headers;

use OAuth::Lite2;
use OAuth::Lite2::Util qw(build_content);
use OAuth::Lite2::Error;
use OAuth::Lite2::Formatters;

sub new {

    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        id                => 1,
        secret            => 1,
        format            => { optional => 1 },
        authorize_url     => { optional => 1 },
        access_token_url  => { optional => 1 },
        refresh_token_url => { optional => 1 },
        agent             => { optional => 1 },
    });

    my $self = bless {
        id                => undef,
        secret            => undef,
        authorize_url     => undef,
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

    return $self;
}

sub url_to_redirect {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        redirect_uri => 1,
        state     => { optional => 1 },
        scope     => { optional => 1 },
        immediate => { optional => 1 },
        url       => { optional => 1 },
        extra     => { optional => 1, type => HASHREF },
    });

    my %params = (
        type         => 'web_server',
        client_id    => $self->{id},
        redirect_uri => $args{redirect_uri},
    );

    $params{state}     = $args{state}     if $args{state};
    $params{scope}     = $args{scope}     if $args{scope};
    $params{immediate} = $args{immediate} if $args{immediate};

    if ($args{extra}) {
        for my $key ( keys %{$args{extra}} ) {
            $params{$key} = $args{extra}{$key};
        }
    }

    my $url = $args{url}
        || $self->{authorize_url}
        || Carp::croak "url not found";

    my $uri = URI->new($url);
    $uri->query_form(%params);
    return $uri->as_string;
}

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        code         => 1,
        redirect_uri => 1,
        secret_type  => { optional => 1 },
        format       => { optional => 1 },
        url          => { optional => 1 },
    });

    unless (exists $args{url}) {
        $args{url} = $self->{access_token_url}
            || Carp::croak "url not found";
    }

    $args{format} ||= $self->{format};

    my %params = (
        type          => 'web_server',
        client_id     => $self->{id},
        client_secret => $self->{secret},
        code          => $args{code},
        redirect_uri  => $args{redirect_uri},
        format        => $args{format},
    );

    $params{secret_type} = $args{secret_type}
        if $args{secret_type};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{url}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my $formatter =
        OAuth::Lite2::Formatters->get_formatter_by_type($res->content_type);
    my $result = $formatter->parse($res->content);

}

sub refresh_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        refresh_token => 1,
        secret_type   => { optional => 1 },
        format        => { optional => 1 },
        url           => { optional => 1 },
    });

    unless (exists $args{url}) {
        $args{url} = $self->{access_token_url}
            || Carp::croak "url not found";
    }

    $args{format} ||= $self->{format};

    my %params = (
        type          => 'refresh',
        client_id     => $self->{id},
        client_secret => $self->{secret},
        refresh_token => $args{refresh_token},
        format        => $args{format},
    );

    $params{secret_type} = $args{secret_type}
        if $args{secret_type};

    my $content = build_content(\%params);
    my $headers = HTTP::Headers->new;
    $headers->header("Content-Type" => q{application/x-www-form-urlencoded});
    $headers->header("Content-Length" => bytes::length($content));
    my $req = HTTP::Request->new( POST => $args{url}, $headers, $content );

    my $res = $self->{agent}->request($req);

    my $formatter =
        OAuth::Lite2::Formatters->get_formatter_by_type($res->content_type);
    my $result = $formatter->parse($res->content);

}

1;
