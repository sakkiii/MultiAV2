import configparser


class SafeConfigParserExtended(configparser.SafeConfigParser):
    def gets(self, section, option, default):
        if self.has_option(section, option):
            return self.get(section, option)
        return default
