import React, {useState} from "react";
import { shuffleAnswers } from "../library/functions";
import PrintScore from "./printScore";
import PrintQuestion from "./printQuestion";
import PrintAnswers from "./printAnswers";

export default function TakeQuiz(props){
    const [currentQuestion, setCurrentQuestion] = useState(0);
    const [currentScore, setCurrentScore] = useState(0);
    const [quizCompleted, setQuizCompleted] = useState(props.isQuestionListEmpty);
    const [selectedAnswer, setSelectedAnswer] = useState("");
    const [shuffledAnswerList, setShuffledAnswerList] = useState(shuffleAnswers(props.questions, 0));

    
    function handleAnswerOptionClick(isCorrect){

        if (isCorrect)
            setCurrentScore(currentScore + 1);

        var nextQuestion = currentQuestion + 1;
        if (nextQuestion == props.questions.length)
            setQuizCompleted(true);
        else
            setShuffledAnswerList(shuffleAnswers(props.questions, nextQuestion));
        
        setCurrentQuestion(nextQuestion);
    }

    return(
        <div className='container divide-y-2 text-left'>
            {quizCompleted ? 
                <>
                    <PrintScore 
                        currentScore = {currentScore}
                        currentQuestion = {currentQuestion}
                        scoreText = {"Final Score: "}
                    />
                    <div className = "flex flex-col items-center">
                        <button className="tracking-wider p-2.5 border-2 border-gray-400  bg-gray-200 box-content my-20 text-2xl font-bold bg-cover" onClick={props.resetQuiz}>RETAKE QUIZ</button>
                    </div>
                </>
            :
                <>
                    <PrintQuestion 
                        currentQuestion = {currentQuestion}
                        numQuestions = {props.numQuestions}
                        questions = {props.questions}
                    />
                    <div className="font-bold ">
                        <PrintAnswers 
                            currentQuestion = {currentQuestion}
                            questions = {props.questions}
                            handleAnswers = {handleAnswerOptionClick}
                            setSelectedAnswer = {setSelectedAnswer}
                            selectedAnswer = {selectedAnswer}
                            shuffledAnswerList = {shuffledAnswerList}
                        />
                    </div>
                </>
            }
        </div>

    )
}