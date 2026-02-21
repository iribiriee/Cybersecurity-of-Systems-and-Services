from fabric import Connection

#changed the original code because of an error during the authentication.
c = Connection(
    host="localhost", 
    user="iribiriee", 
    connect_kwargs={"password": "12345"}
)

c.run("echo Running on local machine")