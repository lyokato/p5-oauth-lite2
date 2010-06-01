package OAuth::Lite2::Client::UsernameAndPassword;

use strict;
use warnings;

use Params::Validate qw(HASHREF);
use Carp ();
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
        access_token_url  => { optional => 1 },
        refresh_token_url => { optional => 1 },
        agent             => { optional => 1 },
    });

    my $self = bless {
        id                => undef,
        secret            => undef,
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

sub get_access_token {
    my $self = shift;

    my %args = Params::Validate::validate(@_, {
        username     => 1,
        password     => 1,
        scope        => { optional => 1 },
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
        type          => 'username',
        client_id     => $self->{id},
        client_secret => $self->{secret},
        username      => $args{username},
        password      => $args{password},
        format        => $args{format},
    );

    $params{scope} = $args{scope}
        if $args{scope};

    $params{secret_type} = $args{secret_type}
        if $args{secret_type};

    my $req = HTTP::Request->new( POST => $args{url} );
    $req->content_type(q{application/x-www-form-urlencoded});
    $req->content( build_content(\%params) );

    my $res = $self->{agent}->request($req);

    my $formatter =
        OAuth::Lite2::Formatters->get_formatter_by_type($res->content_type);
    my $result = $formatter->parse($res->content);

}

1;
