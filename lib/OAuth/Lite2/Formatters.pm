package OAuth::Lite2::Formatters;

use strict;
use warnings;

use OAuth::Lite2::Formatter::JSON;
use OAuth::Lite2::Formatter::XML;
use OAuth::Lite2::Formatter::FormURLEncoded;

my %FORMATTERS;

sub _add_formatter {
    my ($class, $formatter) = @_;
    $FORMATTERS{$formatter->name} = $formatter;
}

__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::JSON->new );
__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::XML->new );
__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::FormURLEncoded->new );

sub get_formatter {
    my ($class, $type) = @_;
    return unless $type;
    return $FORMATTERS{$type};
}

1;
