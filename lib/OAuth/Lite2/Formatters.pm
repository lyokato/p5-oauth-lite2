package OAuth::Lite2::Formatters;

use strict;
use warnings;

use OAuth::Lite2::Formatter::JSON;
use OAuth::Lite2::Formatter::XML;
use OAuth::Lite2::Formatter::FormURLEncoded;

my %FORMATTERS_BY_TYPE;
my %FORMATTERS_BY_NAME;

sub _add_formatter {
    my ($class, $formatter) = @_;
    $FORMATTERS_BY_NAME{$formatter->name} = $formatter;
    $FORMATTERS_BY_TYPE{$formatter->type} = $formatter;
}

__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::JSON->new );
__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::XML->new );
__PACKAGE__->_add_formatter( OAuth::Lite2::Formatter::FormURLEncoded->new );

sub get_formatter_by_name {
    my ($class, $name) = @_;
    return unless $name;
    return $FORMATTERS_BY_NAME{$name};
}

sub get_formatter_by_type {
    my ($class, $type) = @_;
    return unless $type;
    return $FORMATTERS_BY_TYPE{$type};
}

1;
