package OAuth::Lite2::Formatter::JSON;

use strict;
use warnings;

use base 'OAuth::Lite2::Formatter';

use JSON;
use Try::Tiny;
use OAuth::Lite2::Error;

sub name { "json" }
sub type { "application/json" };

sub format {
    my ($self, $hash) = @_;
    return JSON->new->encode($hash);
}

sub parse {
    my ($self, $json) = @_;
    return try { return JSON->new->decode($json) }
        catch {
            OAuth::Lite2::Error::InvalidFormat->throw(
                message => "Parse Error: " . $_);
        };
}

1;
