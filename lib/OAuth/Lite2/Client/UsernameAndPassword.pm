package OAuth::Lite2::Client::UsernameAndPassword;

use strict;
use warnings;

use Params::Validate;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {});
    my $self = bless {}, $class;
    return $self;
}

sub get_access_token {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        username => 1,
        password => 1,
    });
}

sub refresh_access_token {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {
        refresh_token => 1,
    });
}

1;
