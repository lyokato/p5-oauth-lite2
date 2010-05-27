package OAuth::Lite2::Client::UserAgent;

use strict;
use warnings;

use Params::Validate qw(HASHREF);
use URI;
use LWP::UserAgent;
use HTTP::Request;

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
        state       => { optional => 1 },
        scope       => { optional => 1 },
        immediate   => { optional => 1 },
        secret_type => { optional => 1 },
        url         => { optional => 1 },
        extra       => { optional => 1, type => HASHREF },
    });

    my %params = (
        type         => 'user_agent',
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

1;
