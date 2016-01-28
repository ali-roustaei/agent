<?php namespace Jenssegers\Agent;

use BadMethodCallException;
use Mobile_Detect;

class Agent extends Mobile_Detect {

    /**
     * List of desktop devices.
     *
     * @var array
     */
    protected static $additionalDevices = array(
        'Macintosh'        => 'Macintosh',
    );

    /**
     * List of additional operating systems.
     *
     * @var array
     */
    protected static $additionalOperatingSystems = array(
        'Windows'           => 'Windows',
        'Windows NT'        => 'Windows NT',
        'OS X'              => 'Mac OS X',
        'Debian'            => 'Debian',
        'Ubuntu'            => 'Ubuntu',
        'Macintosh'         => 'PPC',
        'OpenBSD'           => 'OpenBSD',
        'Linux'             => 'Linux',
        'ChromeOS'          => 'CrOS',
    );

    /**
     * List of additional browsers.
     *
     * @var array
     */
    protected static $additionalBrowsers = array(
        'Opera'             => 'Opera|OPR',
        'Edge'              => 'Edge',
        'Chrome'            => 'Chrome',
        'Firefox'           => 'Firefox',
        'Safari'            => 'Safari',
        'IE'                => 'MSIE|IEMobile|MSIEMobile|Trident/[.0-9]+',
        'Netscape'          => 'Netscape',
        'Mozilla'           => 'Mozilla',
    );

    /**
     * List of additional properties.
     *
     * @var array
     */
    protected static $additionalProperties = array(
        // Operating systems
        'Windows'           => 'Windows NT [VER]',
        'Windows NT'        => 'Windows NT [VER]',
        'OS X'              => 'OS X [VER]',
        'BlackBerryOS'      => array('BlackBerry[\w]+/[VER]', 'BlackBerry.*Version/[VER]', 'Version/[VER]'),
        'AndroidOS'         => 'Android [VER]',
        'ChromeOS'          => 'CrOS x86_64 [VER]',

        // Browsers
        'Opera'             => array(' OPR/[VER]', 'Opera Mini/[VER]', 'Version/[VER]', 'Opera [VER]'),
        'Netscape'          => 'Netscape/[VER]',
        'Mozilla'           => 'rv:[VER]',
        'IE'                => array('IEMobile/[VER];', 'IEMobile [VER]', 'MSIE [VER];', 'rv:[VER]'),
    );

    /**
     * List of robots.
     *
     * @var array
     */
    protected static $robots = array(
        'Google'            => 'googlebot',
        'MSNBot'            => 'msnbot',
        'Baiduspider'       => 'baiduspider',
        'Bing'              => 'bingbot',
        'Yahoo'             => 'yahoo',
        'Lycos'             => 'lycos',
        'Facebook'          => 'facebookexternalhit',
        'Twitter'           => 'Twitterbot',
        //
        '007ac9'            => '007ac9',
        '5bot'              => '5bot',
        'A6-Indexer'        => 'A6-Indexer',
        'AbachoBOT'         => 'AbachoBOT',
        'Accoona'           => 'accoona',
        'AcoiRobot'         => 'AcoiRobot',
        'AddThis.com'       => 'AddThis.com',
        'ADmantX'           => 'ADmantX',
        'Advbot'            => 'advbot',
        'AhrefsBot'         => 'AhrefsBot',
        'AiHitBot'          => 'aiHitBot',
        'Alexa'             => 'alexa',
        'Alphabot'          => 'alphabot',
        'AltaVista'         => 'AltaVista',
        'AntivirusPro'      => 'AntivirusPro',
        'Anyevent'          => 'anyevent',
        'Appie'             => 'appie',
        'Applebot'          => 'Applebot',
        'archive.org_bot'   => 'archive.org_bot',
        'Ask Jeeves'        => 'Ask Jeeves',
        'ASPSeek'           => 'ASPSeek',
        'Benjojo'           => 'Benjojo',
        'BeetleBot'         => 'BeetleBot',
        'Blekkobot'         => 'Blekkobot',
        'Blexbot'           => 'blexbot',
        'BOT for JCE'       => 'BOT for JCE',
        'bubing'            => 'bubing',
        'Butterfly'         => 'Butterfly',
        'cbot'              => 'cbot',
        'clamantivirus'     => 'clamantivirus',
        'cliqzbot'          => 'cliqzbot',
        'clumboot'          => 'clumboot',
        'coccoc'            => 'coccoc',
        'crawler'           => 'crawler',
        'CrocCrawler'       => 'CrocCrawler',
        'crowsnest.tv'      => 'crowsnest.tv',
        'dbot'              => 'dbot',
        'dl2bot'            => 'dl2bot',
        'dotbot'            => 'dotbot',
        'downloadbot'       => 'downloadbot',
        'duckduckgo'        => 'duckduckgo',
        'Dumbot'            => 'Dumbot',
        'EasouSpider'       => 'EasouSpider',
        'eStyle'            => 'eStyle',
        'EveryoneSocialBot' => 'EveryoneSocialBot',
        'Exabot'            => 'Exabot',
        'ezooms'            => 'ezooms',
        'facebook.com'      => 'facebook.com',
        'FAST'              => 'FAST',
        'FeedfetcherGoogle' => 'Feedfetcher-Google',
        'feedzirra'         => 'feedzirra',
        'findxbot'          => 'findxbot',
        'Firfly'            => 'Firfly',
        'FriendFeedBot'     => 'FriendFeedBot',
        'froogle'           => 'froogle',
        'GeonaBot'          => 'GeonaBot',
        'Gigabot'           => 'Gigabot',
        'girafabot'         => 'girafabot',
        'gimme60bot'        => 'gimme60bot',
        'glbot'             => 'glbot',
        'GroupHigh'         => 'GroupHigh',
        'ia_archiver'       => 'ia_archiver',
        'IDBot'             => 'IDBot',
        'InfoSeek'          => 'InfoSeek',
        'inktomi'           => 'inktomi',
        'IstellaBot'        => 'IstellaBot',
        'jetmon'            => 'jetmon',
        'Kraken'            => 'Kraken',
        'Leikibot'          => 'Leikibot',
        'linkapediabot'     => 'linkapediabot',
        'linkdexbot'        => 'linkdexbot',
        'LinkpadBot'        => 'LinkpadBot',
        'LoadTimeBot'       => 'LoadTimeBot',
        'looksmart'         => 'looksmart',
        'ltx71'             => 'ltx71',
        'Mail.RU_Bot'       => 'Mail.RU_Bot',
        'Me.dium'           => 'Me.dium',
        'meanpathbot'       => 'meanpathbot',
        'mediabot'          => 'mediabot',
        'medialbot'         => 'medialbot',
        'MediaPrtnrsGoogle' => 'Mediapartners-Google',
        'MJ12bot'           => 'MJ12bot',
        'MojeekBot'         => 'MojeekBot',
        'monobot'           => 'monobot',
        'moreover'          => 'moreover',
        'MRBOT'             => 'MRBOT',
        'NationalDirectory' => 'NationalDirectory',
        'NerdyBot'          => 'NerdyBot',
        'NetcraftSurveyAgt' => 'NetcraftSurveyAgent',
        'niki-bot'          => 'niki-bot',
        'nutch'             => 'nutch',
        'Openbot'           => 'Openbot',
        'OrangeBot'         => 'OrangeBot',
        'owler'             => 'owler',
        'p4Bot'             => 'p4Bot',
        'PaperLiBot'        => 'PaperLiBot',
        'pageanalyzer'      => 'pageanalyzer',
        'PagesInventory'    => 'PagesInventory',
        'Pimonster'         => 'Pimonster',
        'porkbun'           => 'porkbun',
        'pr-cy'             => 'pr-cy',
        'proximic'          => 'proximic',
        'pwbot'             => 'pwbot',
        'r4bot'             => 'r4bot',
        'rabaz'             => 'rabaz',
        'Rambler'           => 'Rambler',
        'Rankivabot'        => 'Rankivabot',
        'revip'             => 'revip',
        'riddler'           => 'riddler',
        'rogerbot'          => 'rogerbot',
        'Scooter'           => 'Scooter',
        'Scrubby'           => 'Scrubby',
        'scrapy.org'        => 'scrapy.org',
        'SearchmetricsBot'  => 'SearchmetricsBot',
        'sees.co'           => 'sees.co',
        'SemanticBot'       => 'SemanticBot',
        'SemrushBot'        => 'SemrushBot',
        'SeznamBot'         => 'SeznamBot',
        'sfFeedReader'      => 'sfFeedReader',
        'shareaholic-bot'   => 'shareaholic-bot',
        'sistrix'           => 'sistrix',
        'SiteExplorer'      => 'SiteExplorer',
        'Slurp'             => 'Slurp',
        'Socialradarbot'    => 'Socialradarbot',
        'SocialSearch'      => 'SocialSearch',
        'Sogou web spider'  => 'Sogou web spider',
        'Spade'             => 'Spade',
        'spbot'             => 'spbot',
        'SpiderLing'        => 'SpiderLing',
        'SputnikBot'        => 'SputnikBot',
        'Superfeedr'        => 'Superfeedr',
        'SurveyBot'         => 'SurveyBot',
        'TechnoratiSnoop'   => 'TechnoratiSnoop',
        'TECNOSEEK'         => 'TECNOSEEK',
        'Teoma'             => 'Teoma',
        'trendictionbot'    => 'trendictionbot',
        'TweetmemeBot'      => 'TweetmemeBot',
        'Twiceler'          => 'Twiceler',
        'Twitturls'         => 'Twitturls',
        'u2bot'             => 'u2bot',
        'uMBot-LN'          => 'uMBot-LN',
        'uni5download'      => 'uni5download',
        'unrulymedia'       => 'unrulymedia',
        'URL_Spider_SQL'    => 'URL_Spider_SQL',
        'Vagabondo'         => 'Vagabondo',
        'vBSEO'             => 'vBSEO',
        'WASALive-Bot'      => 'WASALive-Bot',
        'WebAlta Crawler'   => 'WebAlta Crawler',
        'WebBug'            => 'WebBug',
        'WebFindBot'        => 'WebFindBot',
        'WebMasterAid'      => 'WebMasterAid',
        'WeSEE'             => 'WeSEE',
        'Wotbox'            => 'Wotbox',
        'wsowner'           => 'wsowner',
        'wsr-agent'         => 'wsr-agent',
        'www.galaxy.com'    => 'www.galaxy.com',
        'x100bot'           => 'x100bot',
        'XoviBot'           => 'XoviBot',
        'xzybot'            => 'xzybot',
        'Yandex'            => 'yandex',
        'Yammybot'          => 'Yammybot',
        'YoudaoBot'         => 'YoudaoBot',
        'ZyBorg'            => 'ZyBorg',
        'ZemlyaCrawl'       => 'ZemlyaCrawl'
    );

    /**
     * Get all detection rules. These rules include the additional
     * platforms and browsers.
     *
     * @return array
     */
    public function getDetectionRulesExtended()
    {
        static $rules;

        if (!$rules)
        {
            $rules = $this->mergeRules(
                static::$additionalDevices, // NEW
                static::$phoneDevices,
                static::$tabletDevices,
                static::$operatingSystems,
                static::$additionalOperatingSystems, // NEW
                static::$browsers,
                static::$additionalBrowsers, // NEW
                static::$utilities
            );
        }

        return $rules;
    }

    /**
     * Retrieve the current set of rules.
     *
     * @return array
     */
    public function getRules()
    {
        if ($this->detectionType == static::DETECTION_TYPE_EXTENDED)
        {
            return static::getDetectionRulesExtended();
        }
        else
        {
            return static::getMobileDetectionRules();
        }
    }

    /**
     * Get accept languages.
     *
     * @return array
     */
    public function languages($acceptLanguage = null)
    {
        if (! $acceptLanguage)
        {
            $acceptLanguage = $this->getHttpHeader('HTTP_ACCEPT_LANGUAGE');
        }

        if ($acceptLanguage)
        {
            $languages = array();

            // Parse accept language string.
            foreach (explode(',', $acceptLanguage) as $piece)
            {
                $parts = explode(';', $piece);

                $language = strtolower($parts[0]);

                $priority = empty($parts[1]) ? 1. : floatval(str_replace('q=', '', $parts[1]));

                $languages[$language] = $priority;
            }

            // Sort languages by priority.
            arsort($languages);

            return array_keys($languages);
        }

        return array();
    }

    /**
     * Match a detection rule and return the matched key.
     *
     * @param  array  $rules
     * @param  null   $userAgent
     * @return string
     */
    protected function findDetectionRulesAgainstUA(array $rules, $userAgent = null)
    {
        // Loop given rules
        foreach ($rules as $key => $regex)
        {
            if (empty($regex)) continue;

            // Check match
            if ($this->match($regex, $userAgent)) return $key ?: reset($this->matchesArray);
        }

        return false;
    }

    /**
     * Get the browser name.
     *
     * @return string
     */
    public function browser($userAgent = null)
    {
        // Get browser rules
        // Here we need to test for the additional browser first, otherwise
        // MobileDetect will mostly detect Chrome as the browser.
        $rules = $this->mergeRules(
            static::$additionalBrowsers, // NEW
            static::$browsers
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Get the platform name.
     *
     * @param  string $userAgent
     * @return string
     */
    public function platform($userAgent = null)
    {
        // Get platform rules
        $rules = $this->mergeRules(
            static::$operatingSystems,
            static::$additionalOperatingSystems // NEW
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Get the device name.
     *
     * @param  string $userAgent
     * @return string
     */
    public function device($userAgent = null)
    {
        // Get device rules
        $rules = $this->mergeRules(
            static::$additionalDevices, // NEW
            static::$phoneDevices,
            static::$tabletDevices,
            static::$utilities
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Check if the device is a desktop computer.
     *
     * @param  string $userAgent   deprecated
     * @param  array  $httpHeaders deprecated
     * @return bool
     */
    public function isDesktop($userAgent = null, $httpHeaders = null)
    {
        return (! $this->isMobile() && ! $this->isTablet() && ! $this->isRobot());
    }

    /**
     * Check if the device is a mobile phone.
     *
     * @param  string $userAgent   deprecated
     * @param  array  $httpHeaders deprecated
     * @return bool
     */
    public function isPhone($userAgent = null, $httpHeaders = null)
    {
        return ($this->isMobile() && ! $this->isTablet());
    }

    /**
     * Get the robot name.
     *
     * @param  string $userAgent
     * @return string
     */
    public function robot($userAgent = null)
    {
        // Get bot rules
        $rules = $this->mergeRules(
            static::$robots, // NEW
            array(static::$utilities['Bot']),
            array(static::$utilities['MobileBot'])
        );

        return $this->findDetectionRulesAgainstUA($rules, $userAgent);
    }

    /**
     * Check if device is a robot.
     *
     * @param  string  $userAgent
     * @return bool
     */
    public function isRobot($userAgent = null)
    {
        // Get bot rules
        $rules = $this->mergeRules(
            array(static::$utilities['Bot']),
            array(static::$utilities['MobileBot']),
            static::$robots // NEW
        );

        foreach ($rules as $regex)
        {
            // Check for match
            if ($this->match($regex, $userAgent)) return true;
        }

        return false;
    }

    /**
     * Check the version of the given property in the User-Agent.
     *
     * @inherit
     */
    public function version($propertyName, $type = self::VERSION_TYPE_STRING)
    {
        $check = key(static::$additionalProperties);

        // Check if the additional properties have been added already
        if ( ! array_key_exists($check, parent::$properties))
        {
            // TODO: why is mergeRules not working here?
            parent::$properties = array_merge(
                parent::$properties,
                static::$additionalProperties
            );
        }

        return parent::version($propertyName, $type);
    }
    
    /**
     * Get the referrer address
     *
     */
    public function referrer()
    {
        return ( ! isset($_SERVER['HTTP_REFERER']) OR $_SERVER['HTTP_REFERER'] == '') ? false : trim($_SERVER['HTTP_REFERER']);
    }
    
    /**
     * Check request is referral or not
     *
     */
    public function isReferral()
    {
        return ( ! isset($_SERVER['HTTP_REFERER']) OR $_SERVER['HTTP_REFERER'] == '') ? false : true;
    }

    /**
     * Merge multiple rules into one array.
     *
     * @return array
     */
    protected function mergeRules()
    {
        $merged = array();

        foreach (func_get_args() as $rules)
        {
            foreach ($rules as $key => $value)
            {
                if (empty($merged[$key]))
                {
                    $merged[$key] = $value;
                }
                else
                {
                    if (is_array($merged[$key]))
                    {
                        $merged[$key][] = $value;
                    }
                    else
                    {
                        $merged[$key] .= '|' . $value;
                    }
                }
            }
        }

        return $merged;
    }

    /**
     * Changing detection type to extended.
     *
     * @inherit
     */
    public function __call($name, $arguments)
    {
        // Make sure the name starts with 'is', otherwise
        if (substr($name, 0, 2) != 'is')
        {
            throw new BadMethodCallException("No such method exists: $name");
        }

        $this->setDetectionType(self::DETECTION_TYPE_EXTENDED);

        $key = substr($name, 2);

        return $this->matchUAAgainstKey($key);
    }

}
