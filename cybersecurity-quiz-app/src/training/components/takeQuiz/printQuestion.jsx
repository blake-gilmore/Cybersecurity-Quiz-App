import React from "react";
import ChooseAnswerPrompt from "./chooseAnswerPrompt";

export default function PrintQuestion(props){
    return(
        <>
            <ChooseAnswerPrompt />
            <div className='container w-9/12'>
                <div className='text-4xl font-bold underline my-4'> Question {props.currentQuestion+1} / {props.numQuestions} </div> <br/>
                <div className='text-2xl font-black'> {props.questions[props.currentQuestion].question} </div> <br/>
            </div>
        </>
    )
}