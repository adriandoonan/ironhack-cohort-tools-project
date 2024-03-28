const express = require("express");
const morgan = require("morgan");

const cookieParser = require("cookie-parser");
const cors = require("cors");

//ERROR HANDLER
const {
  errorHandler,
  notFoundHandler,
  AppError,
} = require("./middleware/error-handling");

// swagger stuff
const bodyParser = require("body-parser");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const swaggerDocument = require("./oas-base.json");

const PORT = 5005;

const Student = require("./models/Students.model");
const Cohort = require("./models/Cohort.model");

// INITIALIZE EXPRESS APP - https://expressjs.com/en/4x/api.html#express
const app = express();

//MONGOOSE
const mongoose = require("mongoose");

mongoose
  .connect("mongodb://127.0.0.1:27017/cohort-tools-api")
  .then((x) => console.log(`Connected to Database: "${x.connections[0].name}"`))
  .catch((err) => console.error("Error connecting to MongoDB", err));

// MIDDLEWARE
// Research Team - Set up CORS middleware here:
// ...
app.use(
  cors({
    origin: ["http://localhost:5173", "http://example.com"], // Add the URLs of allowed origins to this array
  })
);

// MIDDLEWARE
// Research Team - Set up CORS middleware here:
// ...

const options = {
  definition: swaggerDocument,
  apis: ["./app.js", "./models/*.js"],
  swaggerOptions: {
    url: "/api-docs/oas.json",
  },
};

const specs = swaggerJsdoc(options);
app.get("/api-docs/oas.json", (req, res) => res.json(specs));
app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(specs, { explorer: false })
);

app.use(
  cors({
    origin: ["http://localhost:5173", "http://example.com"], // Add the URLs of allowed origins to this array
  })
);

app.use(express.json());
app.use(morgan("dev"));
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ROUTES - https://expressjs.com/en/starter/basic-routing.html
// Devs Team - Start working on the routes here:
// ...

app.get("/open-api-docs", (req, res) => {
  res.sendFile(`${__dirname}/views/stoplight.html`);
});

/**
 * @swagger
 * tags:
 *   name: Docs
 *   description: The docs
 * /docs:
 *   get:
 *     summary: Lists all the API operations
 *     tags: [Docs]
 *     responses:
 *       200:
 *         description: The endpoints supported by this API
 *         content:
 *           application/json:
 *             schema:
 *               type: string
 *               items:
 *                 type: html
 */
app.get("/docs", (req, res) => {
  res.sendFile(`${__dirname}/views/docs.html`);
});

//create student
app.post("/api/students", (req, res, next) => {
  Student.create(req.body)
    .then((createdStudent) => {
      console.log("Student created ->", createdStudent);
      res.status(201).json(createdStudent);
    })
    .catch((error) => {
      next(error);
    });
});

//retrieve all students
/**
 * @swagger
 * tags:
 *   name: Students
 *   description: The students
 * /students:
 *   get:
 *     summary: Lists all the students
 *     tags: [Students]
 *     responses:
 *       200:
 *         description: The students at Ironhack
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/student"
 */
app.get("/api/students", (req, res, next) => {
  Student.find({})
    .populate("cohort")
    .then((students) => {
      console.log("found students ->", students);
      res.json(students);
    })
    .catch((error) => {
      next(error);
    });
});

//get specific student by ID
app.get("/api/students/:studentId", (req, res, next) => {
  const { studentId } = req.params;

  Student.findById(studentId)
    .populate("cohort")
    .then((student) => {
      if (!student) {
        throw new AppError("student not found", 404);
      }
      console.log("Found student ->", student);

      res.status(200).json(student);
    })
    .catch((error) => {
      next(error);
    });
});

//update specific student by ID
app.put("/api/students/:studentId", (req, res, next) => {
  const { studentId } = req.params;

  Student.findByIdAndUpdate(studentId, req.body, { new: true })
    .then((updateStudent) => {
      if (!updateStudent) {
        throw new AppError("updated student not found", 404);
      }
      console.log("Updated student ->", updateStudent);

      res.status(200).json(updateStudent);
    })
    .catch((error) => {
      next(error);
    });
});

//delete a student
app.delete("/api/students/:studentId", (req, res, next) => {
  const { studentId } = req.params;
  Student.findByIdAndDelete(studentId)
    .then((student) => {
      if (!student) {
        throw new AppError("student not deleted", 404);
      }
      console.log("Student deleted!");
      res.status(204).json({ message: "student deleted successfully" });
    })
    .catch((error) => {
      next(error);
    });
});

//retrieve all students from given cohort
app.get("/api/students/cohort/:cohortId", (req, res, next) => {
  const { cohortId } = req.params;

  Student.find({ cohort: cohortId })
    .populate("cohort")
    .then((studentsByCohort) => {
      if (!studentsByCohort) {
        throw new AppError("student by cohort not found", 404);
      }
      console.log("Found students by cohort ->", studentsByCohort);
      res.status(200).json(studentsByCohort);
    })
    .catch((error) => {
      next(error);
    });
});

// Cohort Routes

//create cohort
app.post("/api/cohorts", (req, res, next) => {
  Cohort.create(req.body)
    .then((newCohort) => {
      // if (!newCohort) {
      //   throw new AppError("student not deleted", 404);
      // }
      console.log("new cohort added", newCohort);
      res.status(201).json(newCohort);
    })
    .catch((error) => {
      next(error);
    });
});

//retrieve all cohorts from collection
/**
 * @swagger
 * tags:
 *   name: Cohorts
 *   description: The cohorts
 * /cohorts:
 *   get:
 *     summary: Lists all the cohorts
 *     tags: [Cohorts]
 *     responses:
 *       200:
 *         description: The cohorts at Ironhack
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/cohort"
 */
app.get("/api/cohorts", (req, res, next) => {
  Cohort.find({})
    .then((cohorts) => {
      if (!cohorts) {
        throw new AppError("cohorts not found", 404);
      }
      console.log("found cohorts ->", cohorts);
      res.json(cohorts);
    })
    .catch((error) => {
      next(error);
    });
});

//single cohort
app.get("/api/cohorts/:cohortId", (req, res, next) => {
  const { cohortId } = req.params;
  Cohort.findById(cohortId)
    .then((cohort) => {
      if (!cohort) {
        throw new AppError("cohort by ID not found", 404);
      }
      console.log("found cohort", Cohort);
      res.status(200).json(cohort);
    })
    .catch((error) => {
      next(error);
    });
});

//update cohort
app.put("/api/cohorts/:cohortId", (req, res, next) => {
  const { cohortId } = req.params;
  Cohort.findByIdAndUpdate(cohortId, req.body, { new: true })
    .then((updateCohort) => {
      if (!updateCohort) {
        throw new AppError("cohort to update not found", 404);
      }
      console.log("updated cohort", updateCohort);
      res.status(200).json(updateCohort);
    })
    .catch((error) => {
      next(error);
    });
});

//delete cohort using the ID
app.delete("/api/cohorts/:cohortId", (req, res, next) => {
  const { cohortId } = req.params;
  Cohort.findByIdAndDelete(cohortId)
    .then((cohort) => {
      if (!cohort) {
        throw new AppError("cohort to delete not found", 404);
      }
      console.log("Cohort deleted!");
      res.status(204).json({ message: "cohort deleted successfully" });
    })
    .catch((error) => {
      next(error);
    });
});

//Error handler
app.use(errorHandler);

//Not found handler
app.use(notFoundHandler);

// START SERVER
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
