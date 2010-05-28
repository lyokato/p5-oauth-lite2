package OAuth::Lite2::Client;

use strict;
use warnings;

use Params::Validate;

sub new {

}

sub refresh_access_token {

}

sub request {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        method              => 1,
        url                 => 1,
        access_token        => 1,
        access_token_secret => { optional => 1 },
        refresh_token       => { optional => 1 },
        headers             => { optional => 1 },
    });

    my $params = ($self->{secret_type})
        ? OAuth::Lite2::Signer->sign(
            secret    => $args{access_token_secret},
            algorithm => $self->{secret_type},
            method    => $args{method},
            url       => $args{url},
        )
        : {};

    my $req = HTTP::Request->new($args{method},
        $args{url}, $args{headers});

    my $res = $self->{agent}->request($req);

    return $res if $res->is_success;

    if (   $self->{on_refresh}
        && ref $self->{on_refresh} eq 'CODE'
        && $args{refresh_token} ) {
        my $refreshed = $self->refresh_access_token(
            refresh_token => $args{refresh_token},
        );
        if ($refreshed) {
            $self->{on_refresh}->($refreshed);
        }
    }
}

sub get {
    my $self = shift;
    my $url  = shift;
    my %args = Params::Validate::validate(@_, {
        
    });
    $args{method} = 'GET';
    $args{url} = $url;
}

sub post {
    my $self = shift;
    my $url  = shift;
    my %args = Params::Validate::validate(@_, {
        
    });
    $args{method} = 'POST';
    $args{url} = $url;
}

sub put {
    my $self = shift;
    my $url  = shift;
    my %args = Params::Validate::validate(@_, {
        
    });
    $args{method} = 'PUT';
    $args{url} = $url;
}

sub delete {
    my $self = shift;
    my $url  = shift;
    my %args = Params::Validate::validate(@_, {
        
    });
    $args{method} = 'DELETE';
    $args{url} = $url;
}

1;
