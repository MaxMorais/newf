from newf import Application

@Application.route       
def foo():
	return response("<h1>Hello World!</h1>")

@Application.route
def _request():
	return response(dict(request)).json

@Application.route(r'^/bar$')
def bar():
	return redirect("/foo")

@Application.route(slashed=True)    
def test_debug():
	raise Exception, 'I am the exception'

@Application.route
def json():
	return response({"Hello": "World!"}).json

application = Application(debug=True)

if __name__ == '__main__':
	from wsgiref.simple_server import make_server
	server = make_server('', 8000, application)
	server.serve_forever()
