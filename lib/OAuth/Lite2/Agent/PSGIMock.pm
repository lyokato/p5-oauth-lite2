package OAuth::Lite2::Agent::PSGIMock;

use strict;
use warnings;

use Params::Validate qw(CODEREF);
use HTTP::Response;
use HTTP::Message::PSGI;
use Try::Tiny;

=head1 NAME


OAuth::Lite2::Agent::PSGIMock - Agnent class for test which use PSGI App

=head2 SYNOPSIS

    use Test::More;

    my $endpoit = OAuth::Lite2::Server::Endpoint::Token->new(
        data_handler => 'YourApp::DataHandler',
    );

    my $agent = OAuth::Lite2::Agent::PSGIMock->new( app => $endpoint );

    my $client = OAuth::Lite2::Client::UsernameAndPassword->new(
        client_id     => q{foo},
        client_secret => q{bar},
        agent         => $agent, 
    );

    my $res = $client->get_access_token(
        username => q{buz},
        password => q{huga},
        scope    => q{email},
    );

    is($res->access_token, ...);
    is($res->refresh_token, ...);


=head1 DESCRIPTION

This class is useful for test to check if your PSGI based
server application acts as expected.

=cut

sub new {
    my $class = shift;

    my %args = Params::Validate::validate(@_, {
        app => { type => CODEREF },     
    });

    my $self = bless {
        app => $args{app}, 
    }, $class; 

    return $self;
}

sub request {
    my ($self, $req) = @_;
    my $res = try {
        HTTP::Response->from_psgi($self->{app}->($req->to_psgi));
    } catch {
        HTTP::Response->from_psgi([500, [ "Content-Type" => "text/plain" ], [ $_ ] ]);
    };
    return $res;
}

1;
