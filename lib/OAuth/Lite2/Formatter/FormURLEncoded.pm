package OAuth::Lite2::Formatter::FormURLEncoded;

use strict;
use warnings;

use base 'OAuth::Lite2::Formatter';

use OAuth::Lite2::Util qw(
    build_content
    parse_content);

sub name { "form" }
sub type { "application/x-www-form-urlencoded" }

sub format {
    my ($self, $hash) = @_;
    return build_content($hash);
}

sub parse {
    my ($self, $content) = @_;
    return parse_content($content);
}

1;
