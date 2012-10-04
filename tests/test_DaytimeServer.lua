package.path = package.path..";..\\Bhut\\?.lua;..\\Bhut\\core\\?.lua";

local Server = require "DaytimeServer"

Server.Startup({port = 9091});

