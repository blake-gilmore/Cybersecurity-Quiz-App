import React from "react"
export default function PrintScore(props){
    return (<div className='text-2xl font-black'> {props.scoreText} {props.currentScore}/{props.currentQuestion} </div>)
}