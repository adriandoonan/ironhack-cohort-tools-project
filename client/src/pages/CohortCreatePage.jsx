import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { createCohortSlug, convertSlugToName } from "../utils/index";

// Import the string from the .env with URL of the API/server - http://localhost:5005
const API_URL = import.meta.env.VITE_API_URL;

const DEFAULT_COHORT_FORM_VALUES = {
	cohortSlug: "format-program-campus-startDate",
	cohortName: "",
	format: "",
	program: "",
	campus: "",
	startDate: "2030-01-01",
	endDate: "2030-01-01",
	inProgress: false,
	programManager: "",
	leadTeacher: "",
	totalHours: 0,
};

function CohortCreatePage() {
	const [cohort, setCohort] = useState({ ...DEFAULT_COHORT_FORM_VALUES });

	const navigate = useNavigate();

	const handleChange = (e) => {
		const { name, value, type, checked } = e.target;

		const cohortSlug = createCohortSlug({ ...cohort, [name]: value });
		const cohortName = convertSlugToName(cohortSlug);

		setCohort((prevCohort) => ({
			...prevCohort,
			cohortSlug,
			cohortName,
			[name]: type === "checkbox" ? checked : value,
		}));
	};

	const handleSubmit = (e) => {
		e.preventDefault();

		const requestBody = {
			...cohort,
		};

		axios
			.post(`${API_URL}/api/cohorts`, requestBody)
			.then((response) => {
				const newCohort = response.data;

				navigate(`/cohorts/details/${newCohort._id}`);
			})
			.catch((error) => console.log(error));
	};

	return (
		<div className="relative flex flex-col w-full h-full max-w-3xl p-8 pb-16 mx-auto mt-10 mb-10 rounded-lg shadow-md CohortCreatePage">
			<div className="absolute top-0 left-0 right-0 flex items-center justify-center py-2 pt-8 mb-4 bg-white border-b border-gray-300 shadow-sm bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200"></div>

			<form
				onSubmit={handleSubmit}
				className="grid grid-cols-1 gap-4 px-4 mt-12 overflow-y-auto"
			>
				<h3 className="sticky left-0 mb-6 text-2xl font-semibold text-gray-700">
					Create Cohort
				</h3>

				<label
					htmlFor="cohortSlug"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Cohort Id
				</label>
				<input
					type="text"
					name="cohortSlug"
					id="cohortSlug"
					value={cohort.cohortSlug}
					onChange={handleChange}
					disabled
					className="w-full p-2 mb-6 border rounded"
				/>

				<label
					htmlFor="cohortName"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Cohort Name
				</label>
				<input
					type="text"
					name="cohortName"
					id="cohortName"
					value={cohort.cohortName}
					onChange={handleChange}
					disabled
					required
					className="w-full p-2 mb-6 border rounded"
				/>

				<label
					htmlFor="format"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Format
				</label>
				<select
					name="format"
					id="format"
					value={cohort.format}
					onChange={handleChange}
					className="w-full p-2 mb-6 border rounded bg-gray-50"
				>
					<option value="">-- Select Format --</option>
					<option value="Full Time">Full Time</option>
					<option value="Part Time">Part Time</option>
				</select>

				<label
					htmlFor="program"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Program
				</label>
				<select
					name="program"
					id="program"
					value={cohort.program}
					onChange={handleChange}
					className="w-full p-2 mb-6 border rounded bg-gray-50"
				>
					<option value="">-- Select Program --</option>
					<option value="Web Dev">Web Development</option>
					<option value="UX/UI">UX/UI</option>
					<option value="Data Analytics">Data Analytics</option>
					<option value="Cybersecurity">Cybersecurity</option>
				</select>

				<label
					htmlFor="campus"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Campus
				</label>
				<select
					name="campus"
					id="campus"
					value={cohort.campus}
					onChange={handleChange}
					className="w-full p-2 mb-6 border rounded bg-gray-50"
				>
					<option value="">-- Select Campus --</option>
					<option value="Madrid">Madrid</option>
					<option value="Barcelona">Barcelona</option>
					<option value="Miami">Miami</option>
					<option value="Paris">Paris</option>
					<option value="Berlin">Berlin</option>
					<option value="Amsterdam">Amsterdam</option>
					<option value="Lisbon">Lisbon</option>
					<option value="Remote">Remote</option>
				</select>

				<label
					htmlFor="startDate"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Start Date:
				</label>
				<input
					type="date"
					name="startDate"
					id="startDate"
					value={cohort.startDate}
					onChange={handleChange}
					className="w-full h-10 p-2 mb-6 border rounded bg-gray-50"
				/>

				<label
					htmlFor="endDate"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					End Date:
				</label>
				<input
					type="date"
					name="endDate"
					id="endDate"
					value={cohort.endDate}
					onChange={handleChange}
					className="w-full h-10 p-2 mb-6 border rounded bg-gray-50"
				/>

				<div className="flex items-center mt-6 mb-6">
					<label
						htmlFor="inProgress"
						className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
					>
						In Progress
					</label>
					<input
						type="checkbox"
						name="inProgress"
						id="inProgress"
						value={cohort.inProgress}
						onChange={handleChange}
						className="relative mt-2 leading-tight -left-24"
					/>
				</div>

				<label
					htmlFor="programManager"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Program Manager
				</label>
				<input
					type="text"
					name="programManager"
					id="programManager"
					value={cohort.programManager}
					onChange={handleChange}
					required
					className="w-full p-2 mb-6 border rounded"
				/>

				<label
					htmlFor="leadTeacher"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Lead Teacher
				</label>
				<input
					type="text"
					name="leadTeacher"
					id="leadTeacher"
					value={cohort.leadTeacher}
					onChange={handleChange}
					required
					className="w-full p-2 mb-6 border rounded"
				/>

				<label
					htmlFor="totalHours"
					className="ml-1 -mb-2 font-bold text-left text-gray-600 text-l"
				>
					Total Hours
				</label>
				<input
					type="number"
					name="totalHours"
					id="totalHours"
					value={cohort.totalHours}
					onChange={handleChange}
					className="w-full p-2 mb-6 border rounded"
				/>

				<button
					type="submit"
					className="px-4 py-2 mt-4 font-bold text-white transition duration-150 ease-in-out bg-blue-500 rounded hover:bg-blue-600"
				>
					Create Cohort
				</button>
			</form>
		</div>
	);
}

export default CohortCreatePage;
