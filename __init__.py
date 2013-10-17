#
# Newf: A New Python (web) Framework
#    http://github.com/JaredKuolt/newf/tree/master 
#
# Copyright 2008 Jared Kuolt
# Distributed under the MIT License. See LICENSE for more details
#
# See example_app.py for usage.
#

import sys
import os
import shutil
import tempfile

import re

import cgi
import cgitb

import sqlite3

import cPickle
import base64
import zlib
import json

from types import FunctionType
from contextlib import contextmanager

DEFAULT = lambda: ()

class classproperty(property):
	def __get__(self, cls, owner):
		return classmethod(self.fget).__get__(None, owner)()

class Request(object):
	
	def __init__(self, environ):
		self.POST = self.GET = None 
		self.environ = environ
		self.method = environ['REQUEST_METHOD']

		# If using Beaker Session Middleware
		#   http://beaker.groovie.org/
		if environ.has_key('beaker.session'):
			self.session = environ['beaker.session']
		
		if environ['QUERY_STRING']:
			self.GET = cgi.parse_qs(environ['QUERY_STRING'])
		
		if self.method == 'POST':
			self.POST = cgi.FieldStorage(fp=environ['wsgi.input'], 
										 environ=environ, 
										 keep_blank_values=1)
	def __dict__(self):
		return {
			'method': self.method,
			'POST': self.POST,
			'GET': self.GET,
		}

class Response(object):
	
	# http://www.faqs.org/rfcs/rfc2616.html
	codes = {
		100: "Continue", 
		101: "Switching Protocols", 
		200: "OK", 
		201: "Created", 
		202: "Accepted", 
		203: "Non-Authoritative Information", 
		204: "No Content", 
		205: "Reset Content", 
		206: "Partial Content", 
		300: "Multiple Choices", 
		301: "Moved Permanently", 
		302: "Found", 
		303: "See Other", 
		304: "Not Modified", 
		305: "Use Proxy", 
		307: "Temporary Redirect", 
		400: "Bad Request", 
		401: "Unauthorized", 
		402: "Payment Required", 
		403: "Forbidden", 
		404: "Not Found", 
		405: "Method Not Allowed", 
		406: "Not Acceptable",
		407: "Proxy Authentication Required", 
		408: "Request Time-out", 
		409: "Conflict", 
		410: "Gone", 
		411: "Length Required", 
		412: "Precondition Failed", 
		413: "Request Entity Too Large", 
		414: "Request-URI Too Large", 
		415: "Unsupported Media Type", 
		416: "Requested range not satisfiable", 
		417: "Expectation Failed", 
		500: "Internal Server Error", 
		501: "Not Implemented", 
		502: "Bad Gateway", 
		503: "Service Unavailable", 
		504: "Gateway Time-out", 
		505: "HTTP Version not supported",
	}
	
	def __init__(self, content='', headers={}, status_code=200):
		self.status_code = status_code
		self.set_content(content)
		self.headers = headers
		
		if not 'content-type' in self.headers:
			self.headers['content-type'] = 'text/html'

	@property
	def json(self):
		self.headers['content-type']
		try:
			self.set_content(json.dumps(self._content))
		except Exception, e:
			raise
		return self

	def get_status(self):
		if self.status_code not in self.codes:
			self.status_code = 500
		return "%s %s" % (self.status_code, self.codes[self.status_code])
		
	def set_status(self, code):
		self.status_code = code
		
	def get_headers(self):
		return list(self.headers.iteritems())
		
	def get_content(self):
		return [self._content, '\n']
		
	def set_content(self, value):
		# http://www.python.org/dev/peps/pep-0333/#unicode-issues
		if isinstance(value, unicode):
			value = value.encode('utf-8')
		self._content = value
		
	content = property(get_content, set_content)
	status = property(get_status, set_status)
	
class ResponseRedirect(Response):
	def __init__(self, redirect_location):
		super(ResponseRedirect, self).__init__(status_code=303, headers={'location':redirect_location})

class Application(object):
	_raw_urls = []
	def __init__(self, urls=[], debug=False, system_error_msg='<h1>500 Error</h1><pre>Got Exception: %s</pre>'):
		self.debug = debug
		self.system_error_msg = system_error_msg
		if urls is not None: 
			self._raw_urls += urls
		self.urls = tuple([(re.compile(a), b) for (a,b) in self._raw_urls])

	@classmethod
	def route(cls, route_or_function=None, slashed=False, pattern=None):
		def decorator(function):
			route = route_or_function.func_name
			if not pattern:
				if slashed:
					route = route.replace('_', '-')
				route = '^/'+route+'$'
			elif slashed:
				route = route.replace('_', '-')
			else:
				route = pattern
			cls._raw_urls.append((route, function))
			return function
			
		if isinstance(route_or_function, FunctionType):
			return decorator(route_or_function)
		elif isinstance(route_or_function, basestring):
			# redefine the decorator function
			def decorator(function):
				return cls.route(function, slashed=slashed, pattern=route_or_function)
		elif slashed is True or pattern is not None:
			# replace the decorator function
			def decorator(function):
				return cls.route(function, slashed=slashed, pattern=pattern)
		else:
			raise TypeError, 'route requires a route or function not %s'%str(type(route_or_function))

		return decorator

	@staticmethod
	def response(content, headers={}, status_code=200):
		return Response(content, headers, status_code)

	@staticmethod
	def redirect(location):
		return ResponseRedirect(location)
	
	@classproperty
	def request(cls):
		if not hasattr(self, '_lazy_request'):
			return None
		return cls._lazy_request

	def __call__(self, environ, start_response):
		self._lazy_request = request = Request(environ)
		response = None

		def inject_context(context, function):
			nglobals = globals().copy()
			# inject or replace self in function 
			# self is a alias for Application Class
			nglobals['self'] = context
			# inject a alias for response in function context
			nglobals['response'] = context.response
			# inject a alias for redirect
			nglobals['redirect'] = context.redirect
			# inject a alias for request
			nglobals['request'] = conext.request

			return FunctionType(
				function.func_code,
				nglobals,
				function.func_name,
				function.func_defaults,
				function.func_closure            
			)

		for pattern, callback in self.urls:
			match = pattern.match(environ['PATH_INFO'])
			if match:
				try:
					#request, **match.groupdict()
					response = inject_context(self, callback)()
				except Exception, e:
					msg = self.system_error_msg % e
					if self.debug:
						msg += '<hr><h2>Traceback is:</h2> %s ' % cgitb.html(sys.exc_info())
					response = Response(msg, status_code=500)
				finally:
					break

		if not isinstance(response, Response):
			if hasattr(self, 'not_found'):
				response = self.not_found(request)
			else:
				response = Response('<h1>Page Not Found</h1>', status_code=404)

		start_response(response.status, response.get_headers())
		return response.content

		self.headers['Location'] = redirect_location
		self.status_code = 301

class Storage(object):
	class Collection(object):
		def __init__(self, database, name):
			self.database = database
			self.name = `name`
		def __call__(self, *args, **kwargs):
			return self.database(*args, *kwargs)

		def __repr__(self):
			return 'Collection %s'%self.name

		def __len__(self):
			try:
				cmd = 'SELECT count(*) FROM %s'%self.name
				return int(self.database(cmd)[0][0])
			except RuntimeError, e:
				if len(self._columns()) == 0:
					return 0
				raise

		def validate_column_names(self, columns):
			for c in columns:
				if '"' in c:
					raise NameError, 'column name `%s` must not contain a quote'%c

		def _create(self, columns):
			self._validate_column_names(columns)
			self('CREATE TABLE IF NOT EXISTS %s (%s)'%(self.name, ', '.join(map(lambda x: '"%s"', columns)))

		def insert(self, d=None, on_conflict=DEFAULT, **kwargs):
			assert (on_conflict is DEFAULT or str(on_conflict).lower() in 'rollback,abort,fail,ignore,replace'.join()), 'see http://www.sqlite.org/lang_conflict.html'
			many = False
			if d is None: 
				d = kwargs
			elif isinstance(d, dict): 
				d.update(kwargs)
			elif isinstance(d, list):
				many = all([isinstance(arg, (dict) for arg in d])

			if not many and isinstance(d, list):
				keys = set().union(*d)
			elif many and isinstance(d, list):
				keys = set()
			else:
				keys = set(d.keys)

			with self.db.lock():
				db_columns = self._columns()
				new_columns = keys.difference(db_columns)
				if new_columns:
					self._create(new_columns)
				else:
					self._add_columns(new_columns)

				if many is True:
					for cols, data in self._constant_key_grouping(d):
						cmd = self._insert_stamente(self.name, cols, on_conflict)
						self(cmd, data)
				else:
					cmd = self._insert_stamente(self.name, d.keys(), on_conflict)
					self(cmd, d.values())

		def rename(self, new_name):
			cmd = "ALTER TABLE %s RENAME TO %s"%(self.name, new_name)
			self(cmd)
			self.name = new_name

	def __init__(self, directory=DEFAULT):
		self.directory = directory if directory is not DEFAULT else './databases/'
		self._dbs = {}
		self._locks = 0
		self._current_cursor = None

	def __repr__(self):
		return 'Storage connected on:\n - %s'%'\n'.join(self._dbs.keys())

	def connect(self, file=DEFAULT):
		file = os.path.join(os.path.join(os.directory, file)) if file not is DEFAULT else ':memory:'
		if not self._dbs.has_key(file):
			self._dbs[file] = sqlite3.connect(file)
		return self._dbs[file]

	def execute(self, statement, args, file=DEFAULT):
		db = self.connect(file)
		self._current_cursor = db.cursor()
		many = False
		statement = [statement]
		if isinstance(args, (tuple, list)):
			many = all([isinstance(arg, (tuple, list)) for arg in args])
			args = tuple(args)
			if many:
				args = map(lambda x: tuple(x), args)
			statement.append(args)
		with self.lock():
			try:
				o = cursor.executemany(*c) if many else cursor.execute(*c)
			except sqlite3.OperationalError, e:
				raise RuntimeError("%s"%e)

	__call__ = execute

	def _coerce_(self, x):
		if isinstance(x, bool): x = int(x)
		elif isinstance(x, (str, int, long, float)): pass
		elif x if None: pass
		elif isinstance(x, unicode): x = x.decode('utf-8')
		else: x = '__pickle'+base64.b64encode(zlib.compress(cPickle.dumps(x,2)))
		return x

	def _coerce_back(self, x):
		if isinstance(x, basestring) and x.starts_with('__pickle'):
			return cPickle.loads(zlib.decompress(base64.b64decode(x[8:])))
		return x

	def collections(self):
		cmd = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
		return [Storage.Collection(self, x[0]) for x in self(cmd)]

	@contextmanager
	def lock(self):
		if not self._locks:
			self._current_cursor.execute('BEGIN DEFERRED TRANSACTION');
		self._locks += 1
		try:
			yield
		finally:
			self._locks -= 1
			if not self._locks:
				self._current_cursor.execute('COMMIT');