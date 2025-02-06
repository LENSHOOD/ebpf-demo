CREATE TABLE IF NOT EXISTS nodes (
	id varchar(30) PRIMARY KEY,
	mainstat varchar(100),
	secondarystat varchar(100),
	title varchar(100),
	subtitle varchar(100)
);

CREATE TABLE IF NOT EXISTS edges (
	id varchar(30) PRIMARY KEY,
	source varchar(30),
	target varchar(30),
	thickness float
);