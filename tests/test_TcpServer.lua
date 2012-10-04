package.path = package.path..";..\\Bhut\\?.lua;..\\Bhut\\core\\?.lua";

require "TcpServer".Startup({port = 13}, function(acceptedsock)	
	acceptedsock:Send(os.date("%c"));
	acceptedsock:Send("\r\n");
			
	acceptedsock:CloseDown()
end);
