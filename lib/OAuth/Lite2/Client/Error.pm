package OAuth::Lite2::Client::Error;

use strict;
use warnings;

use overload
    q{""}    => sub { shift->message },
    fallback => 1;

sub default_message { "error" }

sub new {
    my ($class, %args) = @_;
    bless {
        message => $args{message} || $class->default_message,
    }, $class;
}

sub throw {
    my ($class, %args) = @_;
    die $class->new(%args);
}

sub message {
    my $self = shift;
    return $self->{message};
}

package OAuth::Lite2::Client::Error::InvalidResponse;
our @ISA = qw(OAuth::Lite2::Client::Error);
sub default_message { "invalid response" }

package OAuth::Lite2::Client::Error;

1;
