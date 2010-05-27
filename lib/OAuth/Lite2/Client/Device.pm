package OAuth::Lite2::Client::Device;

use strict;
use warnings;

use Params::Validate;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {});
    my $self = bless {}, $class;
    return $self;
}

sub get_code {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {});
}

sub get_access_token {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {});
}

sub refresh_access_token {
    my $self = shift;
    my %args = Params::Validate::validate(@_, {});
}

1;
