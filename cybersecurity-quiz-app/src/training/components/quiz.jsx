import React, {useState} from 'react'
import MakeSelections from './makeSelections/makeSelections';
import TakeQuiz from './takeQuiz/takeQuiz';
import {RandomizeQuestions} from './library/functions'

export default function Quiz(){

    const [randomQuestionList, setRandomQuestionList] = useState([]);
    const [numQuestions, setNumQuestions] = useState([]);
    const [questionsSet, setQuestionsSet] = useState(false);
    const [isQuestionListEmpty, setIsQuestionListEmpty] = useState(true);


    function handleQuestionChange(newValue){
        setQuestionsSet(true);
        setNumQuestions(newValue);
        setRandomQuestionList(RandomizeQuestions(newValue));
        console.log(newValue.length);

        //checks if there has been any values above zero entered
        for (let i = 0; i < newValue.length; i++){
            if (newValue[i].value > 0){
                setIsQuestionListEmpty(false);
                break;
            }
        }
    }

    function resetQuiz(){
        setQuestionsSet(false);
        var blank = [];
        setIsQuestionListEmpty(true);
        setRandomQuestionList(blank);
        setNumQuestions(blank);
    }


    return(
        <div className='my-10'>
            {questionsSet == false ? 
                <MakeSelections 
                    numQuestions = {numQuestions} 
                    handleQuestions = {handleQuestionChange}
                    setNumQuestions = {setNumQuestions}
                    setQuestionsSet = {setQuestionsSet}   
                />
                : 
                <TakeQuiz 
                    questions = {randomQuestionList}
                    numQuestions = {randomQuestionList.length}
                    isQuestionListEmpty = {isQuestionListEmpty}
                    resetQuiz = {resetQuiz}
                />
            }
        </div>
    )
}