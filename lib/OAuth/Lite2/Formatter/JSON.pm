package OAuth::Lite2::Formatter::JSON;

use strict;
use warnings;

use parent 'OAuth::Lite2::Formatter';

use JSON;
use Try::Tiny;

sub name { "json" }
sub type { "application/json" };

sub format {
    my ($self, $hash) = @_;
    return JSON->new->encode($hash);
}

sub parse {
    my ($self, $json) = @_;
    return JSON->new->decode($json);
}

1;
