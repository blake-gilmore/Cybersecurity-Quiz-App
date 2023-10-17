import React from "react";
import { shuffleAnswers } from "../library/functions";

export default function PrintAnswers(props){



    return (
        <div className='text-xl my-5 text-left '>
            {props.shuffledAnswerList.map((answerOption) => (
                <div key = {answerOption}>
                    <button key={answerOption} className={`tracking-wider p-1 border-2 border-gray-400 rounded-lg bg-gray-200 ${props.selectedAnswer === answerOption ? 'border-red-300' : ''}`} onClick={() => props.setSelectedAnswer(answerOption)}>
                        {answerOption}
                    </button>
                    <br/> <br/>
                </div>
            ))} 
            <button onClick = { () => props.handleAnswers(props.selectedAnswer === props.questions[props.currentQuestion].correctAnswer)}>Submit</button>
        </div>
    )
}