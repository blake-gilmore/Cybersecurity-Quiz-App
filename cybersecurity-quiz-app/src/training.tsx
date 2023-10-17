
import { useState } from "react";

import Quiz from "./training/components/quiz";

const TrainingPage = () => {
const [quizStart, setQuizStart] = useState(false);

  return (
  <div className="container font-centurylite h-fit">
        {quizStart ?
          <Quiz/>
          :
          <div className="flex flex-col items-center">
            <button className="tracking-wider p-2.5 border-2 border-gray-400 rounded-lg bg-gray-200 box-content my-20 text-2xl font-bold rounded-lg bg-cover" onClick={()=>setQuizStart(true)}>Begin Practice Quiz</button>
          </div>
        }
    </div>
  );
};

export default TrainingPage