"use strict";

var Xsql = require("./xsql.js");
var Xctrl = require("./xctrl.js");
var multer = require("multer");
const path = require("path");

const v8 = require("v8"),
  os = require("os");
const Auth = require('./util/auth');


//define class
class Xapi {
  constructor(args, mysqlPool, app) {
    this.config = args;
    this.mysql = new Xsql(args, mysqlPool);
    this.app = app;
    this.ctrls = [];
    this.auth = new Auth(args.jwtSecret);

    /**************** START : multer ****************/
    this.storage = multer.diskStorage({
      destination: function(req, file, cb) {
        cb(null, process.cwd());
      },
      filename: function(req, file, cb) {
        console.log(file);
        cb(null, Date.now() + "-" + file.originalname);
      }
    });

    this.upload = multer({ storage: this.storage });
    /**************** END : multer ****************/
  }

  init(cbk) {
    this.mysql.init((err, results) => {
      this.app.use(this.urlMiddleware.bind(this));
      this.setupAuthRoutes();
      let stat = this.setupRoutes();
      this.app.use(this.errorMiddleware.bind(this));
      cbk(err, stat);
    });
  }

  setupAuthRoutes() {
    // Login endpoint
    this.app.post('/api/auth/login', this.login.bind(this));
    
    // Register endpoint
    this.app.post('/api/auth/register', this.register.bind(this));
  }

  async login(req, res) {
    try {
      console.log('Login attempt:', req.body);
      const { username, password } = req.body;
      
      // Query user from database
      const [user] = await this.mysql.exec(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );
      console.log('Fetched user:', user);

      if (!user) {
        console.log('User not found');
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Verify password
      const isValid = await this.auth.comparePassword(password, user.password);
      console.log('Password match result:', isValid);
      
      if (!isValid) {
        console.log('Password mismatch');
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Generate token
      const token = this.auth.generateToken(user);
      console.log('Generated token:', token);
      
      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  async register(req, res) {
    try {
      const { username, password, role = 'user' } = req.body;
      
      // Check if user exists
      const [existingUser] = await this.mysql.query(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );

      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      // Hash password
      const hashedPassword = await this.auth.hashPassword(password);

      // Create user
      const result = await this.mysql.query(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashedPassword, role]
      );

      const user = {
        id: result.insertId,
        username,
        role
      };

      // Generate token
      const token = this.auth.generateToken(user);

      res.status(201).json({
        token,
        user
      });
    } catch (error) {
      res.status(500).json({ message: 'Internal server error' });
    }
  }

  urlMiddleware(req, res, next) {
    // get only request url from originalUrl
    let justUrl = req.originalUrl.split("?")[0];
    let pathSplit = [];

    // split by apiPrefix
    let apiSuffix = justUrl.split(this.config.apiPrefix);

    if (apiSuffix.length === 2) {
      // split by /
      pathSplit = apiSuffix[1].split("/");
      if (pathSplit.length) {
        if (pathSplit.length >= 3) {
          // handle for relational routes
          req.app.locals._parentTable = pathSplit[0];
          req.app.locals._childTable = pathSplit[2];
        } else {
          // handles rest of routes
          req.app.locals._tableName = pathSplit[0];
        }
      }
    }

    next();
  }

  errorMiddleware(err, req, res, next) {
    if (err && err.code) res.status(400).json({ error: err });
    else if (err && err.message)
      res.status(500).json({ error: "Internal server error : " + err.message });
    else res.status(500).json({ error: "Internal server error : " + err });

    next(err);
  }

  asyncMiddleware(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(err => {
        next(err);
      });
    };
  }

  root(req, res) {
    let routes = [];
    routes = this.mysql.getSchemaRoutes(
      false,
      req.protocol + "://" + req.get("host") + this.config.apiPrefix
    );
    routes = routes.concat(
      this.mysql.globalRoutesPrint(
        req.protocol + "://" + req.get("host") + this.config.apiPrefix
      )
    );
    res.json(routes);
  }

  setupRoutes() {
    let stat = {}
    stat.tables = 0
    stat.apis = 0
    stat.routines = 0

    // Apply auth middleware to all routes except public endpoints
    this.app.use((req, res, next) => {
      // Define public endpoints that don't require authentication
      const publicEndpoints = [
        `${this.config.apiPrefix}auth/login`,
        `${this.config.apiPrefix}auth/register`,
        '/_health',
        '/_version',
        '/docs'
      ];

      // Check if the current path is a public endpoint
      if (publicEndpoints.some(endpoint => req.path === endpoint)) {
        return next();
      }

      // Check if the request has a valid JWT token
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({ message: 'No token provided' });
      }

      try {
        // Verify the token
        const decoded = this.auth.verifyToken(token);
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
      }
    });

    // Add documentation route
    this.app.get("/docs", this.asyncMiddleware(async (req, res) => {
      try {
        // Get all tables
        const tables = await this.mysql.exec(
          "SELECT table_name FROM information_schema.tables WHERE table_schema = ?",
          [this.config.database]
        );

        // Get all stored procedures
        const procedures = await this.mysql.exec(
          "SELECT routine_name FROM information_schema.routines WHERE routine_schema = ?",
          [this.config.database]
        );

        // Generate documentation HTML
        const html = this.generateDocumentation(tables, procedures);
        res.send(html);
      } catch (error) {
        console.error('Error generating documentation:', error);
        res.status(500).send('Error generating documentation');
      }
    }));

    // show routes for database schema
    this.app.get("/", this.asyncMiddleware(this.root.bind(this)));

    // show all resouces
    this.app
      .route(this.config.apiPrefix + "tables")
      .get(this.asyncMiddleware(this.tables.bind(this)));

    this.app
      .route(this.config.apiPrefix + "xjoin")
      .get(this.asyncMiddleware(this.xjoin.bind(this)));

    stat.apis += 3;

    /**************** START : setup routes for each table ****************/
    let resources = [];
    resources = this.mysql.getSchemaRoutes(true, this.config.apiPrefix);

    stat.tables += resources.length;

    // iterate over each resource
    for (var j = 0; j < resources.length; ++j) {
      let resourceCtrl = new Xctrl(this.app, this.mysql);
      this.ctrls.push(resourceCtrl);

      let routes = resources[j]["routes"];

      stat.apis += resources[j]["routes"].length;

      // iterate over each routes in resource and map function
      for (var i = 0; i < routes.length; ++i) {
        switch (routes[i]["routeType"]) {
          case "list":
            this.app
              .route(routes[i]["routeUrl"])
              .get(this.asyncMiddleware(resourceCtrl.list.bind(resourceCtrl)));
            break;

          case "findOne":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.findOne.bind(resourceCtrl))
              );
            break;

          case "create":
            if (!this.config.readOnly)
              this.app
                .route(routes[i]["routeUrl"])
                .post(
                  this.asyncMiddleware(resourceCtrl.create.bind(resourceCtrl))
                );
            break;

          case "read":
            this.app
              .route(routes[i]["routeUrl"])
              .get(this.asyncMiddleware(resourceCtrl.read.bind(resourceCtrl)));
            break;

          case "bulkInsert":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .post(
                  this.asyncMiddleware(
                    resourceCtrl.bulkInsert.bind(resourceCtrl)
                  )
                );
            }
            break;

          case "bulkRead":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .get(
                  this.asyncMiddleware(resourceCtrl.bulkRead.bind(resourceCtrl))
                );
            } else {
              stat.apis--;
            }
            break;

          case "bulkDelete":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .delete(
                  this.asyncMiddleware(
                    resourceCtrl.bulkDelete.bind(resourceCtrl)
                  )
                );
            } else {
              stat.apis--;
            }
            break;

          case "patch":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .patch(
                  this.asyncMiddleware(resourceCtrl.patch.bind(resourceCtrl))
                );
            } else {
              stat.apis--;
            }
            break;

          case "update":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .put(
                  this.asyncMiddleware(resourceCtrl.update.bind(resourceCtrl))
                );
            } else {
              stat.apis--;
            }
            break;

          case "delete":
            if (!this.config.readOnly) {
              this.app
                .route(routes[i]["routeUrl"])
                .delete(
                  this.asyncMiddleware(resourceCtrl.delete.bind(resourceCtrl))
                );
            } else {
              stat.apis--;
            }
            break;

          case "exists":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.exists.bind(resourceCtrl))
              );
            break;

          case "count":
            this.app
              .route(routes[i]["routeUrl"])
              .get(this.asyncMiddleware(resourceCtrl.count.bind(resourceCtrl)));
            break;

          case "distinct":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.distinct.bind(resourceCtrl))
              );
            break;

          case "describe":
            this.app
              .route(routes[i]["routeUrl"])
              .get(this.asyncMiddleware(this.tableDescribe.bind(this)));
            break;

          case "relational":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.nestedList.bind(resourceCtrl))
              );
            break;

          case "groupby":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.groupBy.bind(resourceCtrl))
              );
            break;

          case "ugroupby":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.ugroupby.bind(resourceCtrl))
              );
            break;

          case "chart":
            this.app
              .route(routes[i]["routeUrl"])
              .get(this.asyncMiddleware(resourceCtrl.chart.bind(resourceCtrl)));
            break;

          case "autoChart":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.autoChart.bind(resourceCtrl))
              );
            break;

          case "aggregate":
            this.app
              .route(routes[i]["routeUrl"])
              .get(
                this.asyncMiddleware(resourceCtrl.aggregate.bind(resourceCtrl))
              );
            break;
        }
      }
    }
    /**************** END : setup routes for each table ****************/

    if (this.config.dynamic === 1 && !this.config.readOnly) {
      this.app
        .route("/dynamic*")
        .post(this.asyncMiddleware(this.runQuery.bind(this)));

      /**************** START : multer routes ****************/
      this.app.post(
        "/upload",
        this.upload.single("file"),
        this.uploadFile.bind(this)
      );
      this.app.post(
        "/uploads",
        this.upload.array("files", 10),
        this.uploadFiles.bind(this)
      );
      this.app.get("/download", this.downloadFile.bind(this));
      /**************** END : multer routes ****************/

      stat.apis += 4;
    }

    /**************** START : health and version ****************/
    this.app.get("/_health", this.asyncMiddleware(this.health.bind(this)));
    this.app.get("/_version", this.asyncMiddleware(this.version.bind(this)));
    stat.apis += 2;
    /**************** END : health and version ****************/

    /**************** START : call stored procedures ****************/
    this.app.get('/_proc', this.asyncMiddleware(this.proc.bind(this)))
    stat.apis += 1
    const procResources = this.mysql.getProcList(true, this.config.apiPrefix)
    this.app.post('/_proc/:proc', this.asyncMiddleware(this.callProc.bind(this)))
    stat.routines += procResources.length
    stat.apis += procResources.length
    /**************** END : call stored procedures ****************/

    let statStr = '     Generated: ' + stat.apis + ' REST APIs for ' + stat.tables + ' tables '

    console.log(' - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ');
    console.log('                                                            ');
    console.log('          Database              :    %s', this.config.database);
    console.log('          Number of Tables      :    %s', stat.tables);
    console.log('          Number of Routines    :    %s', stat.routines);
    console.log('                                                            ');
    console.log('          REST APIs Generated   :    %s'.green.bold, stat.apis);
    console.log('                                                            ');

    return stat
  }

  async xjoin(req, res) {
    let obj = {};

    obj.query = "";
    obj.params = [];

    this.mysql.prepareJoinQuery(req, res, obj);

    //console.log(obj);
    if (obj.query.length) {
      let results = await this.mysql.exec(obj.query, obj.params);
      res.status(200).json(results);
    } else {
      res.status(400).json({ err: "Invalid Xjoin request" });
    }
  }

  async tableDescribe(req, res) {
    let query = "describe ??";
    let params = [req.app.locals._tableName];

    let results = await this.mysql.exec(query, params);
    res.status(200).json(results);
  }

  async tables(req, res) {
    let query =
      "SELECT table_name AS resource FROM information_schema.tables WHERE table_schema = ? ";
    let params = [this.config.database];

    if (Object.keys(this.config.ignoreTables).length > 0) {
      query += "and table_name not in (?)";
      params.push(Object.keys(this.config.ignoreTables));
    }

    let results = await this.mysql.exec(query, params);

    res.status(200).json(results);
  }

  async runQuery(req, res) {
    let query = req.body.query;
    let params = req.body.params;

    let results = await this.mysql.exec(query, params);
    res.status(200).json(results);
  }

  /**************** START : files related ****************/
  downloadFile(req, res) {
    let file = path.join(process.cwd(), req.query.name);
    res.download(file);
  }

  uploadFile(req, res) {
    if (req.file) {
      console.log(req.file.path);
      res.end(req.file.path);
    } else {
      res.end("upload failed");
    }
  }

  uploadFiles(req, res) {
    if (!req.files || req.files.length === 0) {
      res.end("upload failed");
    } else {
      let files = [];
      for (let i = 0; i < req.files.length; ++i) {
        files.push(req.files[i].path);
      }

      res.end(files.toString());
    }
  }

  /**************** END : files related ****************/

  /**************** START : health and version ****************/

  async getMysqlUptime() {
    let v = await this.mysql.exec("SHOW GLOBAL STATUS LIKE 'Uptime';", []);
    return v[0]["Value"];
  }

  async getMysqlHealth() {
    let v = await this.mysql.exec("select version() as version", []);
    return v[0]["version"];
  }

  async health(req, res) {
    let status = {};
    status["process_uptime"] = process.uptime();
    status["mysql_uptime"] = await this.getMysqlUptime();

    if (Object.keys(req.query).length) {
      status["process_memory_usage"] = process.memoryUsage();
      status["os_total_memory"] = os.totalmem();
      status["os_free_memory"] = os.freemem();
      status["os_load_average"] = os.loadavg();
      status["v8_heap_statistics"] = v8.getHeapStatistics();
    }

    res.json(status);
  }

  async version(req, res) {
    let version = {};

    version["Xmysql"] = this.app.get("version");
    version["mysql"] = await this.getMysqlHealth();
    version["node"] = process.versions.node;
    res.json(version);
  }

  /**************** END : health and version ****************/

  async proc(req, res) {
    let query = 'SELECT routine_name AS resource FROM information_schema.routines WHERE routine_schema = ? ';
    let params = [this.config.database];
    let results = await this.mysql.exec(query, params)
    res.status(200).json(results)
  }

  async callProc(req, res) {
    let query = 'CALL ??(?)'
    let params = [req.params.proc, Object.values(req.body)]
    let results = await this.mysql.exec(query, params)
    res.status(200).json(results)
  }

  generateDocumentation(tables, procedures) {
    const baseUrl = `http://localhost:${this.config.portNumber}`;
    const apiPrefix = this.config.apiPrefix;

    let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XMySQL API Documentation</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
    <style>
        body { font-family: 'Roboto', sans-serif; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { margin-bottom: 20px; }
        .endpoint { font-family: monospace; background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 10px; position: relative; }
        .curl-command { background-color: #263238; color: #fff; padding: 10px; border-radius: 4px; margin-bottom: 10px; overflow-x: auto; position: relative; }
        .response-example { background-color: #e8f5e9; padding: 10px; border-radius: 4px; margin-bottom: 10px; }
        .nav-wrapper { padding: 0 20px; }
        .section { padding-top: 20px; }
        .table-name { color: #2196F3; font-weight: bold; }
        .copy-btn { position: absolute; right: 10px; top: 10px; cursor: pointer; color: #2196F3; }
        .copy-btn:hover { color: #1976D2; }
        .jwt-protected { color: #f44336; font-size: 0.8em; margin-left: 10px; }
        .auth-info { background-color: #fff3e0; padding: 20px; border-radius: 4px; margin-bottom: 20px; }
        .token-input { margin-top: 20px; }
        .token-input input { font-family: monospace; }
        .token-input .btn { margin-left: 10px; }
    </style>
</head>
<body>
    <nav class="blue darken-3">
        <div class="nav-wrapper">
            <a href="#" class="brand-logo">XMySQL API Documentation</a>
        </div>
    </nav>

    <div class="container">
        <div class="section">
            <div class="auth-info">
                <h4>Authentication</h4>
                <p>This API requires JWT authentication. All endpoints except registration and login require a valid JWT token.</p>
                
                <h5>Register a New User</h5>
                <div class="endpoint">
                    POST ${apiPrefix}auth/register
                    <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}auth/register')">content_copy</i>
                </div>
                <div class="curl-command">
                    curl -X POST -H "Content-Type: application/json" -d '{"username":"newuser","password":"password"}' ${baseUrl}${apiPrefix}auth/register
                    <i class="material-icons copy-btn" onclick="copyToClipboard('curl -X POST -H \\"Content-Type: application/json\\" -d \\'{\\"username\\":\\"newuser\\",\\"password\\":\\"password\\"}\\' ${baseUrl}${apiPrefix}auth/register')">content_copy</i>
                </div>
                <div class="response-example">
                    <pre>{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 1,
        "username": "newuser",
        "role": "user"
    }
}</pre>
                </div>

                <h5>Login to Get JWT Token</h5>
                <div class="endpoint">
                    POST ${apiPrefix}auth/login
                    <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}auth/login')">content_copy</i>
                </div>
                <div class="curl-command">
                    curl -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' ${baseUrl}${apiPrefix}auth/login
                    <i class="material-icons copy-btn" onclick="copyToClipboard('curl -X POST -H \\"Content-Type: application/json\\" -d \\'{\\"username\\":\\"test\\",\\"password\\":\\"test\\"}\\' ${baseUrl}${apiPrefix}auth/login')">content_copy</i>
                </div>
                <div class="response-example">
                    <pre>{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 1,
        "username": "test",
        "role": "user"
    }
}</pre>
                </div>

                <h5>Using the JWT Token</h5>
                <p>Include the JWT token in the Authorization header for all protected endpoints:</p>
                <div class="token-input">
                    <div class="input-field">
                        <input type="text" id="jwtToken" placeholder="Paste your JWT token here">
                        <label for="jwtToken">JWT Token</label>
                    </div>
                    <button class="btn waves-effect waves-light" onclick="updateAllCurlCommands()">Update All Commands</button>
                </div>
                <div class="curl-command">
                    curl -H "Authorization: Bearer YOUR_TOKEN_HERE" ${baseUrl}${apiPrefix}tableName
                    <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" ${baseUrl}${apiPrefix}tableName')">content_copy</i>
                </div>
            </div>
        </div>

        <div class="section">
            <h4>Database Tables</h4>
            <p>Total Tables: ${tables.length}</p>
            <div class="row">
                ${tables.map(table => `
                <div class="col s12">
                    <div class="card">
                        <div class="card-content">
                            <h5 class="table-name">${table.table_name}</h5>
                            
                            <h6>List Records <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET ${baseUrl}${apiPrefix}${table.table_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET ${baseUrl}${apiPrefix}${table.table_name}')">content_copy</i>
                            </div>
                            
                            <h6>Get Single Record <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}/:id
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/1">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET ${baseUrl}${apiPrefix}${table.table_name}/1
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET ${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            
                            <h6>Create Record <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                POST ${apiPrefix}${table.table_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -H "Content-Type: application/json" -d '{"field1":"value1"}' ${baseUrl}${apiPrefix}${table.table_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -H \\"Content-Type: application/json\\" -d \\'{\\"field1\\":\\"value1\\"}\\' ${baseUrl}${apiPrefix}${table.table_name}')">content_copy</i>
                            </div>
                            
                            <h6>Update Record <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                PATCH ${apiPrefix}${table.table_name}/:id
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/1">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X PATCH -H "Content-Type: application/json" -d '{"field1":"newValue"}' ${baseUrl}${apiPrefix}${table.table_name}/1
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X PATCH -H \\"Content-Type: application/json\\" -d \\'{\\"field1\\":\\"newValue\\"}\\' ${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            
                            <h6>Delete Record <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                DELETE ${apiPrefix}${table.table_name}/:id
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/1">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X DELETE ${baseUrl}${apiPrefix}${table.table_name}/1
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X DELETE ${baseUrl}${apiPrefix}${table.table_name}/1')">content_copy</i>
                            </div>
                            
                            <h6>Bulk Operations <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                POST ${apiPrefix}${table.table_name}/bulk
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/bulk')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/bulk">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X POST -H "Content-Type: application/json" -d '[{"field1":"value1"},{"field1":"value2"}]' ${baseUrl}${apiPrefix}${table.table_name}/bulk
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X POST -H \\"Content-Type: application/json\\" -d \\'[{\\"field1\\":\\"value1\\"},{\\"field1\\":\\"value2\\"}]\\' ${baseUrl}${apiPrefix}${table.table_name}/bulk')">content_copy</i>
                            </div>
                            
                            <h6>Find One <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}/findOne
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/findOne?_where=(field1,eq,value1)')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/findOne?_where=(field1,eq,value1)">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET "${baseUrl}${apiPrefix}${table.table_name}/findOne?_where=(field1,eq,value1)"
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET \\"${baseUrl}${apiPrefix}${table.table_name}/findOne?_where=(field1,eq,value1)\\"')">content_copy</i>
                            </div>
                            
                            <h6>Count <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}/count
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/count')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/count">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET ${baseUrl}${apiPrefix}${table.table_name}/count
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET ${baseUrl}${apiPrefix}${table.table_name}/count')">content_copy</i>
                            </div>
                            
                            <h6>Distinct <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}/distinct
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/distinct?_fields=field1')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/distinct?_fields=field1">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET "${baseUrl}${apiPrefix}${table.table_name}/distinct?_fields=field1"
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET \\"${baseUrl}${apiPrefix}${table.table_name}/distinct?_fields=field1\\"')">content_copy</i>
                            </div>
                            
                            <h6>Describe Table <span class="jwt-protected">JWT Protected</span></h6>
                            <div class="endpoint">
                                GET ${apiPrefix}${table.table_name}/describe
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}${table.table_name}/describe')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}${table.table_name}/describe">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET ${baseUrl}${apiPrefix}${table.table_name}/describe
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET ${baseUrl}${apiPrefix}${table.table_name}/describe')">content_copy</i>
                            </div>
                        </div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>

        <div class="section">
            <h4>Stored Procedures</h4>
            <p>Total Procedures: ${procedures.length}</p>
            <div class="row">
                ${procedures.map(proc => `
                <div class="col s12">
                    <div class="card">
                        <div class="card-content">
                            <h5 class="table-name">${proc.routine_name} <span class="jwt-protected">JWT Protected</span></h5>
                            <div class="endpoint">
                                POST /_proc/${proc.routine_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}/_proc/${proc.routine_name}')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}/_proc/${proc.routine_name}">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X POST -H "Content-Type: application/json" -d '{"param1":"value1"}' ${baseUrl}/_proc/${proc.routine_name}
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X POST -H \\"Content-Type: application/json\\" -d \\'{\\"param1\\":\\"value1\\"}\\' ${baseUrl}/_proc/${proc.routine_name}')">content_copy</i>
                            </div>
                        </div>
                    </div>
                </div>
                `).join('')}
            </div>
        </div>

        <div class="section">
            <h4>Global Endpoints</h4>
            <div class="row">
                <div class="col s12">
                    <div class="card">
                        <div class="card-content">
                            <h5>XJoin <span class="jwt-protected">JWT Protected</span></h5>
                            <div class="endpoint">
                                GET ${apiPrefix}xjoin
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}${apiPrefix}xjoin?_join=table1,_j,table2&_on1=(table1.id,eq,table2.id)')">content_copy</i>
                            </div>
                            <div class="curl-command" data-endpoint="${baseUrl}${apiPrefix}xjoin?_join=table1,_j,table2&_on1=(table1.id,eq,table2.id)">
                                curl -H "Authorization: Bearer YOUR_TOKEN_HERE" -X GET "${baseUrl}${apiPrefix}xjoin?_join=table1,_j,table2&_on1=(table1.id,eq,table2.id)"
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -H \\"Authorization: Bearer YOUR_TOKEN_HERE\\" -X GET \\"${baseUrl}${apiPrefix}xjoin?_join=table1,_j,table2&_on1=(table1.id,eq,table2.id)\\"')">content_copy</i>
                            </div>
                            
                            <h5>Health Check</h5>
                            <div class="endpoint">
                                GET /_health
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}/_health')">content_copy</i>
                            </div>
                            <div class="curl-command">
                                curl -X GET ${baseUrl}/_health
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -X GET ${baseUrl}/_health')">content_copy</i>
                            </div>
                            
                            <h5>Version Info</h5>
                            <div class="endpoint">
                                GET /_version
                                <i class="material-icons copy-btn" onclick="copyToClipboard('${baseUrl}/_version')">content_copy</i>
                            </div>
                            <div class="curl-command">
                                curl -X GET ${baseUrl}/_version
                                <i class="material-icons copy-btn" onclick="copyToClipboard('curl -X GET ${baseUrl}/_version')">content_copy</i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
    <script>
        function copyToClipboard(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            
            // Show a small toast notification
            M.toast({html: 'Copied to clipboard!'});
        }

        function updateAllCurlCommands() {
            const token = document.getElementById('jwtToken').value;
            if (!token) {
                M.toast({html: 'Please enter a JWT token first!'});
                return;
            }

            // Update all curl commands with the token
            document.querySelectorAll('.curl-command').forEach(command => {
                const endpoint = command.getAttribute('data-endpoint');
                if (endpoint) {
                    const currentText = command.textContent.trim();
                    const newText = currentText.replace('YOUR_TOKEN_HERE', token);
                    command.textContent = newText;
                }
            });

            M.toast({html: 'All commands updated with your token!'});
        }
    </script>
</body>
</html>`;

    return html;
  }

}

//expose class
module.exports = Xapi;
